"""Streamlit user interface for the StegoSeal class-project prototype."""

import io

import streamlit as st
from PIL import Image

from crypto import decrypt_message, encrypt_message, generate_key
from stego import capacity_bytes, embed_payload, extract_payload, image_metrics, tamper_payload

st.set_page_config(page_title="StegoSeal", page_icon="ðŸ”", layout="wide")
st.title("ðŸ” StegoSeal")
st.caption("Encrypt a short message, hide it inside a PNG, and verify whether it was changed.")
st.warning(
    "Educational demonstration only. The generated key is displayed in your browser; share it securely. "
    "This prototype is not a production secure-messaging system. Use PNG throughoutâ€”JPEG or image edits can destroy hidden data."
)

hide_tab, extract_tab, about_tab = st.tabs(["Hide a message", "Extract a message", "How it works"])

with hide_tab:
    st.subheader("Encrypt and hide")
    left, right = st.columns(2)
    with left:
        cover_upload = st.file_uploader("Choose a cover PNG", type=["png"], key="cover")
        message = st.text_area("Message to hide", max_chars=2000, height=140)
        key_text = st.text_input("AES-256 key (leave blank to generate one)", type="password", key="hide_key")
        if cover_upload:
            cover_bytes = cover_upload.getvalue()
            try:
                cover_image = Image.open(io.BytesIO(cover_bytes))
                st.image(cover_image, caption=f"Cover image â€¢ {cover_image.width} Ã— {cover_image.height}", use_container_width=True)
                st.caption(f"Approximate maximum encrypted payload: {capacity_bytes(cover_bytes):,} bytes")
            except ValueError as exc:
                st.error(str(exc))
    with right:
        if st.button("Encrypt and hide message", type="primary", use_container_width=True):
            if not cover_upload:
                st.error("Upload a PNG cover image first.")
            elif not message:
                st.error("Enter a message first.")
            else:
                try:
                    chosen_key = key_text.strip() or generate_key()
                    encrypted = encrypt_message(message, chosen_key)
                    stego_bytes = embed_payload(cover_upload.getvalue(), encrypted)
                    metrics = image_metrics(cover_upload.getvalue(), stego_bytes)
                    st.session_state["stego_result"] = stego_bytes
                    st.session_state["stego_key"] = chosen_key
                    st.session_state["stego_metrics"] = metrics
                    st.success("Message encrypted and embedded successfully.")
                except ValueError as exc:
                    st.error(str(exc))
        if "stego_result" in st.session_state:
            st.image(st.session_state["stego_result"], caption="StegoSeal output PNG", use_container_width=True)
            st.code(st.session_state["stego_key"], language=None)
            st.caption("Save this key. You need the exact key to decrypt the hidden message.")
            st.download_button(
                "Download stego PNG",
                data=st.session_state["stego_result"],
                file_name="stegoseal_output.png",
                mime="image/png",
                use_container_width=True,
            )
            metrics = st.session_state["stego_metrics"]
            st.metric("Changed pixel channels", f"{metrics['changed_channels']:,} / {metrics['total_channels']:,}")
            st.metric("MSE", f"{metrics['mse']:.6f}")
            st.metric("PSNR", "âˆž" if metrics["psnr_db"] == float("inf") else f"{metrics['psnr_db']:.2f} dB")

with extract_tab:
    st.subheader("Extract and decrypt")
    hidden_upload = st.file_uploader("Choose a StegoSeal PNG", type=["png"], key="hidden")
    decrypt_key = st.text_input("AES-256 key", type="password", key="decrypt_key")
    if st.button("Extract and decrypt", type="primary"):
        if not hidden_upload:
            st.error("Upload a StegoSeal PNG first.")
        elif not decrypt_key.strip():
            st.error("Enter the AES-256 key.")
        else:
            try:
                encrypted_payload = extract_payload(hidden_upload.getvalue())
                plaintext = decrypt_message(encrypted_payload, decrypt_key)
                st.success("Authentication passed. Message recovered:")
                st.text_area("Recovered message", plaintext, height=120, disabled=True)
            except ValueError as exc:
                st.error(str(exc))
    st.divider()
    st.subheader("Tampering demonstration")
    st.write("Flip one bit inside the encrypted payload, then try extraction and decryption.")
    if st.button("Create tampered copy", disabled=hidden_upload is None):
        try:
            damaged = tamper_payload(hidden_upload.getvalue())
            st.session_state["tampered_result"] = damaged
            st.success("Tampered copy created. Download it and try it above with the original key.")
        except ValueError as exc:
            st.error(str(exc))
    if "tampered_result" in st.session_state:
        st.download_button(
            "Download tampered PNG",
            data=st.session_state["tampered_result"],
            file_name="stegoseal_tampered.png",
            mime="image/png",
        )

with about_tab:
    st.subheader("What each part does")
    st.markdown(
        """
        1. **AES-256-GCM** encrypts the message and authenticates its contents. A wrong key or changed ciphertext is rejected.
        2. **LSB steganography** stores the encrypted bytes in the least significant bits of RGB pixel channels.
        3. **PNG** preserves those bits. Resizing, lossy compression, or some image-editing operations may destroy them.
        4. Hiding data is not the same as encryption: the message is protected by AES-GCM; LSB only conceals where the data is stored.

        The shared key is generated randomly and shown to the sender. This demo does not provide a secure key-delivery channel.
        """
    )

