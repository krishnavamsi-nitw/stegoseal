"""Simple RGB least-significant-bit (LSB) embedding for PNG images."""

from __future__ import annotations

import io
import math
import struct

from PIL import Image, UnidentifiedImageError

FRAME_MAGIC = b"STG1"
LENGTH_SIZE = 4
HEADER_SIZE = len(FRAME_MAGIC) + LENGTH_SIZE


def _open_png(image_bytes: bytes) -> Image.Image:
    try:
        image = Image.open(io.BytesIO(image_bytes))
        if image.format != "PNG":
            raise ValueError("Please upload a PNG image. Other formats can alter hidden bits.")
        return image.convert("RGB")
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("The uploaded file is not a readable PNG image.") from exc


def capacity_bytes(image_bytes: bytes) -> int:
    """Maximum application payload bytes after frame overhead."""
    image = _open_png(image_bytes)
    return max(0, (image.width * image.height * 3) // 8 - HEADER_SIZE)


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    output = bytearray()
    for index in range(0, len(bits), 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def embed_payload(image_bytes: bytes, payload: bytes) -> bytes:
    """Embed bytes in RGB channel LSBs and return a lossless PNG."""
    if not payload:
        raise ValueError("There is no encrypted payload to hide.")
    image = _open_png(image_bytes)
    framed = FRAME_MAGIC + struct.pack(">I", len(payload)) + payload
    bits = _bytes_to_bits(framed)
    pixels = bytearray(image.tobytes())
    if len(bits) > len(pixels):
        available = max(0, len(pixels) // 8 - HEADER_SIZE)
        raise ValueError(f"Image is too small. Maximum encrypted payload is about {available} bytes.")
    for index, bit in enumerate(bits):
        pixels[index] = (pixels[index] & 0xFE) | bit
    image.putdata([tuple(pixels[i : i + 3]) for i in range(0, len(pixels), 3)])
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=False)
    return output.getvalue()


def extract_payload(image_bytes: bytes) -> bytes:
    """Extract and validate the framed payload from an RGB PNG."""
    image = _open_png(image_bytes)
    pixels = image.tobytes()
    if len(pixels) < HEADER_SIZE * 8:
        raise ValueError("Image is too small to contain a StegoSeal payload.")
    header = _bits_to_bytes([pixels[i] & 1 for i in range(HEADER_SIZE * 8)])
    if header[: len(FRAME_MAGIC)] != FRAME_MAGIC:
        raise ValueError("No StegoSeal payload was found in this image.")
    payload_length = struct.unpack(">I", header[len(FRAME_MAGIC) : HEADER_SIZE])[0]
    total_bits = (HEADER_SIZE + payload_length) * 8
    if payload_length == 0 or total_bits > len(pixels):
        raise ValueError("The embedded length is invalid or the image was modified.")
    framed = _bits_to_bytes([pixels[i] & 1 for i in range(total_bits)])
    return framed[HEADER_SIZE:]


def tamper_payload(image_bytes: bytes) -> bytes:
    """Flip a ciphertext bit while preserving the outer LSB frame."""
    image = _open_png(image_bytes)
    pixels = bytearray(image.tobytes())
    payload = extract_payload(image_bytes)
    # Envelope = 4-byte magic + 12-byte nonce + ciphertext + 16-byte GCM tag.
    if len(payload) < 4 + 12 + 1 + 16:
        raise ValueError("Payload is too short to demonstrate tampering.")
    bit_index = (HEADER_SIZE + 4 + 12) * 8
    pixels[bit_index] ^= 1
    image.putdata([tuple(pixels[i : i + 3]) for i in range(0, len(pixels), 3)])
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=False)
    return output.getvalue()


def image_metrics(original_png: bytes, stego_png: bytes) -> dict[str, float | int]:
    """Report simple visual-change metrics between two same-sized images."""
    original = _open_png(original_png).tobytes()
    modified = _open_png(stego_png).tobytes()
    if len(original) != len(modified):
        raise ValueError("Images must have the same dimensions for comparison.")
    squared_error = sum((a - b) ** 2 for a, b in zip(original, modified))
    mse = squared_error / len(original) if original else 0.0
    changed = sum(a != b for a, b in zip(original, modified))
    psnr = math.inf if mse == 0 else 10 * math.log10((255**2) / mse)
    return {
        "changed_channels": changed,
        "total_channels": len(original),
        "mse": mse,
        "psnr_db": psnr,
    }
