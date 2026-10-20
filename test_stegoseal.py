import io
import unittest

from PIL import Image

from crypto import decrypt_message, encrypt_message, generate_key
from stego import capacity_bytes, embed_payload, extract_payload, image_metrics, tamper_payload


def png_bytes(width=160, height=160):
    image = Image.new("RGB", (width, height), color=(120, 160, 200))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class StegoSealTests(unittest.TestCase):
    def test_encrypt_hide_extract_decrypt_roundtrip(self):
        image = png_bytes()
        key = generate_key()
        encrypted = encrypt_message("hello from StegoSeal", key)
        embedded = embed_payload(image, encrypted)
        recovered = extract_payload(embedded)
        self.assertEqual(decrypt_message(recovered, key), "hello from StegoSeal")

    def test_wrong_key_is_rejected(self):
        envelope = encrypt_message("secret", generate_key())
        with self.assertRaisesRegex(ValueError, "Authentication failed"):
            decrypt_message(envelope, generate_key())

    def test_tampering_is_rejected(self):
        image = png_bytes()
        key = generate_key()
        embedded = embed_payload(image, encrypt_message("secret", key))
        damaged = tamper_payload(embedded)
        with self.assertRaisesRegex(ValueError, "Authentication failed"):
            decrypt_message(extract_payload(damaged), key)

    def test_small_image_fails_with_clear_capacity_error(self):
        with self.assertRaisesRegex(ValueError, "too small"):
            embed_payload(png_bytes(8, 8), b"this payload cannot fit")

    def test_capacity_and_metrics(self):
        image = png_bytes()
        key = generate_key()
        embedded = embed_payload(image, encrypt_message("short", key))
        self.assertGreater(capacity_bytes(image), 0)
        metrics = image_metrics(image, embedded)
        self.assertGreater(metrics["changed_channels"], 0)
        self.assertLessEqual(metrics["mse"], 1)
        self.assertEqual(decrypt_message(extract_payload(embedded), key), "short")


if __name__ == "__main__":
    unittest.main()

