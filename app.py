
"""StegoSeal: Secure Message Encryption and Image Steganography."""

import io

import streamlit as st
from PIL import Image

from crypto import decrypt_message, encrypt_message, generate_key
from stego import (
    capacity_bytes,
    embed_payload,
    extract_payload,
    image_metrics,
    tamper_payload,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="StegoSeal | Secure Image Steganography",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e5eaf5;
}

[data-testid="stHeader"] {
    background-color: rgba(11, 17, 32, 0.95);
}

[data-testid="stMainBlockContainer"] {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}

h1, h2, h3,
[data-testid="stHeading"] {
    color: #f1f5ff !important;
}

p, label, .stMarkdown {
    color: #cbd5e1;
}

/* HERO HEADER */

.hero {
    background: linear-gradient(120deg, #111e38, #172b4d, #10243d);
    border: 1.5px solid #38bdf8;
    border-radius: 22px;
    box-shadow:
        0 0 0 1px rgba(56, 189, 248, 0.12),
        0 8px 28px rgba(0, 0, 0, 0.25);
    padding: 30px 34px;
    margin-bottom: 22px;
    overflow: hidden;
    box-sizing: border-box;
}

.hero-title {
    color: #ffffff;
    font-size: 36px;
    font-weight: 750;
    margin-bottom: 8px;
}

.hero-subtitle {
    color: #b9c9df;
    font-size: 15px;
    margin-bottom: 18px;
}

.hero-tag {
    display: inline-block;
    background: #18385c;
    color: #8bc5ff;
    border: 1px solid #315b85;
    border-radius: 20px;
    padding: 6px 12px;
    font-size: 12px;
    margin-right: 7px;
}

/* SECTION LABELS */

.section-label {
    color: #60a5fa;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 5px;
}

.section-description {
    color: #94a3b8;
    font-size: 14px;
    margin-bottom: 20px;
}

/* INPUT AND ENCRYPTION CARDS */

[data-testid="stVerticalBlockBorderWrapper"] {
    background: #101c30;
    border: 1px solid #294565 !important;
    border-radius: 15px !important;
    padding: 12px;
}

[data-testid="stVerticalBlockBorderWrapper"] > div {
    border-radius: 15px;
}

.panel-heading {
    color: #eaf2ff;
    font-size: 19px;
    font-weight: 700;
    margin-bottom: 8px;
}

.panel-description {
    color: #94a3b8;
    font-size: 13px;
    line-height: 1.6;
    margin-bottom: 16px;
}

.workflow-step {
    background: #142844;
    border: 1px solid #294565;
    border-radius: 10px;
    padding: 12px;
    margin: 12px 0;
    color: #cbd5e1;
    font-size: 13px;
}

/* METRICS */

[data-testid="stMetric"] {
    background: #131f33;
    border: 1px solid #263a57;
    border-radius: 13px;
    padding: 19px;
}

[data-testid="stMetricLabel"] {
    color: #9db2ce !important;
}

[data-testid="stMetricValue"] {
    color: #f1f5ff !important;
    font-weight: 700;
}

/* INPUT FIELDS */

.stTextArea textarea,
.stTextInput input {
    background-color: #131f33 !important;
    color: #f1f5ff !important;
    border: 1px solid #344966 !important;
    border-radius: 10px !important;
}

.stTextArea textarea:focus,
.stTextInput input:focus {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 0 1px #38bdf8 !important;
}

[data-testid="stFileUploader"] {
    background: #131f33;
    border: 1px dashed #42658e;
    border-radius: 12px;
    padding: 12px;
}

/* BUTTONS */

.stButton > button,
.stDownloadButton > button {
    border-radius: 9px;
    font-weight: 600;
    min-height: 43px;
    transition: all 0.2s ease;
}

.stButton > button[kind="primary"] {
    background: #2563eb;
    border: 1px solid #3b82f6;
    color: white;
}

.stButton > button[kind="primary"]:hover {
    background: #1d4ed8;
    border-color: #60a5fa;
}

.stDownloadButton > button {
    background: #142b46;
    border: 1px solid #35618d;
    color: #dbeafe;
}

.stDownloadButton > button:hover {
    background: #1c3b60;
    border-color: #60a5fa;
}

/* TABS: readable inactive labels and a clear active state */

.stTabs [data-baseweb="tab-list"] {
    gap: 20px;
    border-bottom: 1px solid #263a57;
}

/* Streamlit renders the active-tab underline as a separate highlight element. */
.stTabs [data-baseweb="tab-highlight"] {
    background-color: #38bdf8 !important;
    height: 3px !important;
    border-radius: 3px 3px 0 0 !important;
}

/* Apply the text color directly to the tab button and its contents.
   This prevents Streamlit/BaseWeb defaults from making inactive tabs too dark. */
.stTabs button[role="tab"] {
    color: #cbd5e1 !important;
    background: transparent !important;
    font-weight: 600 !important;
    opacity: 1 !important;
    border-radius: 9px 9px 0 0 !important;
    padding: 11px 14px !important;
    transition: color 0.18s ease, background-color 0.18s ease;
}

.stTabs button[role="tab"] p,
.stTabs button[role="tab"] span,
.stTabs button[role="tab"] div {
    color: inherit !important;
    opacity: 1 !important;
}

.stTabs button[role="tab"]:hover {
    color: #7dd3fc !important;
    background: rgba(56, 189, 248, 0.08) !important;
}

.stTabs button[role="tab"][aria-selected="true"] {
    color: #7dd3fc !important;
    background: rgba(37, 99, 235, 0.12) !important;
    border-bottom-color: #38bdf8 !important;
}

.stTabs button[role="tab"][aria-selected="true"] p,
.stTabs button[role="tab"][aria-selected="true"] span,
.stTabs button[role="tab"][aria-selected="true"] div {
    color: #7dd3fc !important;
}

/* ALERTS */

[data-testid="stAlert"] {
    border-radius: 10px;
}

[data-testid="stExpander"] {
    background: #131f33;
    border: 1px solid #365578;
    border-radius: 12px;
    overflow: hidden;
}

[data-testid="stExpander"] summary {
    color: #dbeafe !important;
    font-weight: 600;
    padding: 4px 2px;
}

[data-testid="stExpander"] summary:hover {
    color: #7dd3fc !important;
}

[data-testid="stImage"] {
    background: #0e192b;
    border: 1px solid #294565;
    border-radius: 14px;
    padding: 9px;
    overflow: hidden;
}

[data-testid="stImage"] img {
    border-radius: 9px;
}

.stDownloadButton > button {
    min-height: 48px;
    border-radius: 11px;
    font-size: 14px;
    font-weight: 650;
    letter-spacing: 0.1px;
}

[data-testid="stCode"] {
    border: 1px solid #294565;
    border-radius: 10px;
    overflow: hidden;
}

.output-helper {
    color: #94a3b8;
    font-size: 12px;
    line-height: 1.6;
    margin-top: -5px;
    margin-bottom: 10px;
}

hr {
    border-color: #263a57;
}

/* ABOUT TAB: concise technical overview cards */
.about-intro {
    color: #a9bdd8;
    font-size: 14px;
    line-height: 1.7;
    margin: 4px 0 22px 0;
    max-width: 950px;
}

.about-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
    margin: 18px 0 24px 0;
}

.about-card {
    background: linear-gradient(145deg, #13243b, #101c30);
    border: 1px solid #294565;
    border-radius: 14px;
    padding: 20px 21px;
    min-height: 142px;
    box-sizing: border-box;
}

.about-card-number {
    color: #38bdf8;
    font-size: 11px;
    font-weight: 750;
    letter-spacing: 1.2px;
    margin-bottom: 10px;
}

.about-card h3 {
    color: #edf5ff !important;
    font-size: 17px;
    margin: 0 0 9px 0;
}

.about-card p {
    color: #a9bdd8;
    font-size: 13px;
    line-height: 1.65;
    margin: 0;
}

.about-subheading {
    color: #eaf2ff;
    font-size: 19px;
    font-weight: 700;
    margin: 26px 0 12px 0;
}

.tech-stack {
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
    margin: 12px 0 22px 0;
}

.tech-pill {
    display: inline-block;
    color: #c9e6ff;
    background: #142b46;
    border: 1px solid #31577e;
    border-radius: 20px;
    padding: 7px 12px;
    font-size: 12px;
    font-weight: 600;
}

.security-note {
    background: #17263b;
    border: 1px solid #365578;
    border-left: 4px solid #38bdf8;
    border-radius: 12px;
    padding: 16px 18px;
    color: #bdcce0;
    font-size: 13px;
    line-height: 1.7;
    margin-top: 12px;
}

.security-note strong {
    color: #eaf2ff;
}

@media (max-width: 760px) {
    .about-grid {
        grid-template-columns: 1fr;
    }
    .about-card {
        min-height: auto;
    }
}

/* FOOTER */

.footer {
    text-align: center;
    color: #64748b;
    font-size: 12px;
    padding-top: 25px;
    margin-top: 30px;
    border-top: 1px solid #263a57;
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# HEADER
# ============================================================

hero_html = (
    '<div class="hero">'
    '<div class="hero-title">🔐 StegoSeal</div>'
    '<div class="hero-subtitle">'
    'Secure Message Encryption &amp; Image Steganography'
    '</div>'
    '<span class="hero-tag">AES-256-GCM</span> '
    '<span class="hero-tag">LSB Steganography</span> '
    '<span class="hero-tag">PNG Based</span>'
    '</div>'
)

st.markdown(hero_html, unsafe_allow_html=True)

st.info(
    "Educational demonstration only. AES keys must be shared securely. "
    "This prototype is not a production secure-messaging system. "
    "Use PNG images throughout. JPEG compression or image editing "
    "may destroy hidden data."
)


# ============================================================
# NAVIGATION
# ============================================================

hide_tab, extract_tab, about_tab = st.tabs(
    [
        "🔒 Hide a Message",
        "🔓 Extract a Message",
        "ℹ️ About StegoSeal",
    ]
)


# ============================================================
# TAB 1: ENCRYPT AND HIDE
# ============================================================

with hide_tab:

    st.markdown(
        '<div class="section-label">ENCRYPTION MODULE</div>',
        unsafe_allow_html=True,
    )

    st.subheader("Encrypt and hide your message")

    st.markdown(
        '<div class="section-description">'
        'Select a PNG image, enter your message, and securely embed '
        'the encrypted payload inside the image.'
        '</div>',
        unsafe_allow_html=True,
    )

    left, right = st.columns([1, 1], gap="large")

    # --------------------------------------------------------
    # LEFT: INPUT PANEL
    # --------------------------------------------------------

    with left:

        with st.container(border=True):

            st.markdown("### 01 · Input")

            st.markdown(
                '<div class="panel-description">'
                'Upload a cover image and provide the message '
                'you want to encrypt and conceal.'
                '</div>',
                unsafe_allow_html=True,
            )

            cover_upload = st.file_uploader(
                "Upload cover PNG image",
                type=["png"],
                key="cover",
                help="Only PNG images are supported.",
            )

            message = st.text_area(
                "Message to encrypt",
                placeholder="Enter your confidential sample message here...",
                max_chars=2000,
                height=150,
            )

            key_text = st.text_input(
                "AES-256 key (leave blank to generate automatically)",
                type="password",
                key="hide_key",
            )

            if cover_upload:

                cover_bytes = cover_upload.getvalue()

                try:

                    cover_image = Image.open(
                        io.BytesIO(cover_bytes)
                    )

                    cover_image.load()

                    if cover_image.format != "PNG":
                        st.error("Please upload a valid PNG image.")
                    else:

                        st.markdown(
                            '<div class="panel-description">'
                            '<b>Original cover image</b>'
                            '</div>',
                            unsafe_allow_html=True,
                        )

                        with st.container(border=True):
                            st.image(
                                cover_image,
                                caption=(
                                    f"Original PNG • {cover_image.width} "
                                    f"× {cover_image.height}"
                                ),
                                use_container_width=True,
                            )

                        st.caption(
                            f"Maximum encrypted payload capacity: "
                            f"{capacity_bytes(cover_bytes):,} bytes"
                        )

                except (ValueError, OSError) as exc:

                    st.error(str(exc))

    # --------------------------------------------------------
    # RIGHT: ENCRYPTION PANEL
    # --------------------------------------------------------

    with right:

        with st.container(border=True):

            st.markdown("### 02 · Encryption")

            st.markdown(
                '<div class="panel-description">'
                'Your message is encrypted using AES-256-GCM '
                'before being embedded into the image using '
                'RGB Least Significant Bit steganography.'
                '</div>',
                unsafe_allow_html=True,
            )

            st.markdown(
                """
                <div class="workflow-step">
                    <b>01 · AES-256-GCM</b><br>
                    Encrypts and authenticates your message.
                </div>
                <div class="workflow-step">
                    <b>02 · RGB LSB Embedding</b><br>
                    Conceals the encrypted payload inside image pixels.
                </div>
                <div class="workflow-step">
                    <b>03 · PNG Generation</b><br>
                    Produces the final stego image for download.
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("<br>", unsafe_allow_html=True)

            if st.button(
                "🔐 Encrypt and hide message",
                type="primary",
                use_container_width=True,
            ):

                if not cover_upload:

                    st.error("Please upload a PNG cover image.")

                elif not message:

                    st.error("Please enter a message to encrypt.")

                else:

                    try:

                        cover_bytes = cover_upload.getvalue()

                        cover_image = Image.open(
                            io.BytesIO(cover_bytes)
                        )
                        cover_image.load()

                        if cover_image.format != "PNG":
                            raise ValueError(
                                "Please upload a valid PNG image."
                            )

                        chosen_key = (
                            key_text.strip() or generate_key()
                        )

                        encrypted = encrypt_message(
                            message,
                            chosen_key,
                        )

                        stego_bytes = embed_payload(
                            cover_bytes,
                            encrypted,
                        )

                        metrics = image_metrics(
                            cover_bytes,
                            stego_bytes,
                        )

                        st.session_state["stego_result"] = stego_bytes
                        st.session_state["stego_key"] = chosen_key
                        st.session_state["stego_metrics"] = metrics

                        st.session_state["message_bytes"] = len(
                            message.encode("utf-8")
                        )

                        st.session_state["cover_dimensions"] = (
                            cover_image.width,
                            cover_image.height,
                        )

                        st.success(
                            "Encryption and embedding completed successfully!"
                        )

                    except (ValueError, OSError) as exc:

                        st.error(str(exc))

            # ------------------------------------------------
            # GENERATED OUTPUT
            # ------------------------------------------------

            if "stego_result" in st.session_state:

                st.divider()

                st.markdown("### 03 · Generated Stego Image")

                st.markdown(
                    '<div class="panel-description">'
                    '<b>Encrypted output image</b><br>'
                    'The encrypted payload is now embedded in this PNG.'
                    '</div>',
                    unsafe_allow_html=True,
                )

                with st.container(border=True):
                    st.image(
                        st.session_state["stego_result"],
                        caption="StegoSeal output PNG",
                        use_container_width=True,
                    )

                st.download_button(
                    "⬇️  Download Stego PNG",
                    data=st.session_state["stego_result"],
                    file_name="stegoseal_output.png",
                    mime="image/png",
                    use_container_width=True,
                )

                st.markdown(
                    '<div class="output-helper">'
                    'Download the PNG and preserve it without resizing '
                    'or JPEG conversion.'
                    '</div>',
                    unsafe_allow_html=True,
                )

                with st.expander("🔑  View or copy AES-256 key"):

                    st.markdown(
                        '<div class="output-helper">'
                        'Use the copy control on the key field. Keep this '
                        'key private and retain it for message recovery.'
                        '</div>',
                        unsafe_allow_html=True,
                    )

                    st.code(
                        st.session_state["stego_key"],
                        language=None,
                    )

                    st.warning(
                        "Anyone possessing both this key and the stego "
                        "image can attempt to decrypt the hidden message."
                    )

    # --------------------------------------------------------
    # RESULTS DASHBOARD
    # --------------------------------------------------------

    if "stego_result" in st.session_state:

        st.divider()

        st.markdown(
            '<div class="section-label">PERFORMANCE ANALYSIS</div>',
            unsafe_allow_html=True,
        )

        st.subheader("Image quality and embedding metrics")

        metrics = st.session_state["stego_metrics"]

        metric1, metric2, metric3 = st.columns(3)

        with metric1:

            st.metric(
                "Changed Pixel Channels",
                f"{metrics['changed_channels']:,}",
            )

        with metric2:

            st.metric(
                "Mean Squared Error",
                f"{metrics['mse']:.6f}",
            )

        with metric3:

            psnr_value = metrics["psnr_db"]

            st.metric(
                "PSNR",
                (
                    "∞"
                    if psnr_value == float("inf")
                    else f"{psnr_value:.2f} dB"
                ),
            )

        info1, info2, info3 = st.columns(3)

        with info1:

            width, height = st.session_state["cover_dimensions"]

            st.metric(
                "Image Dimensions",
                f"{width} × {height}",
            )

        with info2:

            st.metric(
                "Message Size",
                f"{st.session_state['message_bytes']} bytes",
            )

        with info3:

            st.metric(
                "Total RGB Channels",
                f"{metrics['total_channels']:,}",
            )

        st.caption(
            "Metrics compare the original cover image with the generated "
            "stego image. PSNR measures pixel-level similarity, not "
            "steganographic undetectability."
        )


# ============================================================
# TAB 2: EXTRACT AND VERIFY
# ============================================================

with extract_tab:

    st.markdown(
        '<div class="section-label">DECRYPTION MODULE</div>',
        unsafe_allow_html=True,
    )

    st.subheader("Extract and decrypt hidden messages")

    st.markdown(
        '<div class="section-description">'
        'Upload a StegoSeal PNG and provide the matching AES-256 key '
        'to authenticate and recover the original message.'
        '</div>',
        unsafe_allow_html=True,
    )

    extract_left, extract_right = st.columns([1, 1], gap="large")

    # --------------------------------------------------------
    # LEFT: EXTRACTION AND DECRYPTION
    # --------------------------------------------------------

    with extract_left:

        with st.container(border=True):

            st.markdown("### 01 · Upload and decrypt")

            st.markdown(
                '<div class="panel-description">'
                'Select the PNG containing the hidden encrypted payload, '
                'then enter the original AES-256 key.'
                '</div>',
                unsafe_allow_html=True,
            )

            hidden_upload = st.file_uploader(
                "Upload StegoSeal PNG",
                type=["png"],
                key="hidden",
                help="Choose the original StegoSeal output PNG.",
            )

            decrypt_key = st.text_input(
                "AES-256 decryption key",
                type="password",
                key="decrypt_key",
            )

            if st.button(
                "🔓 Extract and decrypt",
                type="primary",
                use_container_width=True,
                key="extract_decrypt_button",
            ):

                if not hidden_upload:
                    st.session_state.pop("recovered_message", None)
                    st.error("Please upload a StegoSeal PNG.")

                elif not decrypt_key.strip():
                    st.session_state.pop("recovered_message", None)
                    st.error("Please enter the AES-256 key.")

                else:
                    try:
                        encrypted_payload = extract_payload(
                            hidden_upload.getvalue()
                        )

                        plaintext = decrypt_message(
                            encrypted_payload,
                            decrypt_key,
                        )

                        st.session_state["recovered_message"] = plaintext
                        st.session_state["extract_status"] = "success"

                    except (ValueError, OSError) as exc:
                        st.session_state.pop("recovered_message", None)
                        st.session_state["extract_status"] = "failure"
                        st.session_state["extract_error"] = str(exc)

            if st.session_state.get("extract_status") == "success":
                st.success(
                    "Authentication passed! Message recovered successfully."
                )

            elif st.session_state.get("extract_status") == "failure":
                st.error(
                    "Authentication failed: "
                    "wrong key or the hidden data was changed."
                )
                st.caption(st.session_state.get("extract_error", ""))

            if "recovered_message" in st.session_state:
                st.markdown("#### Recovered message")

                st.code(
                    st.session_state["recovered_message"],
                    language=None,
                )

                st.caption(
                    "The recovered plaintext was returned only after "
                    "AES-GCM authentication succeeded."
                )

    # --------------------------------------------------------
    # RIGHT: TAMPERING DEMONSTRATION
    # --------------------------------------------------------

    with extract_right:

        with st.container(border=True):

            st.markdown("### 02 · Tampering demonstration")

            st.markdown(
                '<div class="panel-description">'
                'Create a modified copy by flipping one bit inside the '
                'encrypted payload. The authentication check should reject it.'
                '</div>',
                unsafe_allow_html=True,
            )

            st.markdown(
                """
                <div class="workflow-step">
                    <b>01 · Select a StegoSeal PNG</b><br>
                    Use the same PNG selected in the extraction panel.
                </div>
                <div class="workflow-step">
                    <b>02 · Modify the payload</b><br>
                    One payload bit is flipped in a separate copy.
                </div>
                <div class="workflow-step">
                    <b>03 · Verify authentication</b><br>
                    AES-256-GCM detects the altered encrypted data.
                </div>
                """,
                unsafe_allow_html=True,
            )

            if st.button(
                "🛡️ Create tampered copy",
                disabled=hidden_upload is None,
                use_container_width=True,
                key="create_tampered_button",
            ):
                try:
                    damaged = tamper_payload(hidden_upload.getvalue())
                    st.session_state["tampered_result"] = damaged
                    st.session_state["tamper_status"] = "success"

                except (ValueError, OSError) as exc:
                    st.session_state["tamper_status"] = "failure"
                    st.session_state["tamper_error"] = str(exc)

            if st.session_state.get("tamper_status") == "success":
                st.success("Tampered PNG created successfully.")
                st.caption(
                    "Download this copy, then upload it in the left panel "
                    "and attempt extraction with the original key."
                )

            elif st.session_state.get("tamper_status") == "failure":
                st.error(
                    st.session_state.get(
                        "tamper_error",
                        "Unable to create the tampered PNG.",
                    )
                )

            if "tampered_result" in st.session_state:
                st.download_button(
                    "⬇️ Download Tampered PNG",
                    data=st.session_state["tampered_result"],
                    file_name="stegoseal_tampered.png",
                    mime="image/png",
                    use_container_width=True,
                    key="download_tampered_png",
                )

                st.markdown(
                    '<div class="output-helper">'
                    'This is a separate modified copy. Your original '
                    'StegoSeal PNG remains unchanged.'
                    '</div>',
                    unsafe_allow_html=True,
                )


# ============================================================
# TAB 3: ABOUT THE PROJECT
# ============================================================

with about_tab:

    st.markdown(
        '<div class="section-label">PROJECT OVERVIEW</div>',
        unsafe_allow_html=True,
    )

    st.subheader("How StegoSeal Works")

    st.markdown(
        '<div class="about-intro">'
        'StegoSeal protects a message with authenticated encryption, then conceals '
        'the encrypted data inside the RGB pixel channels of a PNG image. '
        'The recipient can recover the message only with the matching AES key.'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="about-grid">
            <div class="about-card">
                <div class="about-card-number">01 · ENCRYPTION</div>
                <h3>AES-256-GCM</h3>
                <p>Encrypts the message using a 256-bit key and authenticates the
                encrypted data. An incorrect key or modified payload is rejected.</p>
            </div>
            <div class="about-card">
                <div class="about-card-number">02 · CONCEALMENT</div>
                <h3>RGB LSB Steganography</h3>
                <p>Embeds the encrypted payload in the least significant bits of
                the image's red, green and blue pixel channels.</p>
            </div>
            <div class="about-card">
                <div class="about-card-number">03 · IMAGE FORMAT</div>
                <h3>PNG Processing</h3>
                <p>Uses PNG's lossless storage to preserve embedded pixel values.
                JPEG conversion, resizing or image edits can damage hidden data.</p>
            </div>
            <div class="about-card">
                <div class="about-card-number">04 · RECOVERY</div>
                <h3>Authentication and Decryption</h3>
                <p>Extracts the encrypted payload and verifies it with AES-GCM.
                The original message is returned only when authentication succeeds.</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="about-subheading">Technology Stack</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="tech-stack">
            <span class="tech-pill">Python</span>
            <span class="tech-pill">Streamlit</span>
            <span class="tech-pill">Pillow</span>
            <span class="tech-pill">Cryptography</span>
            <span class="tech-pill">AES-256-GCM</span>
            <span class="tech-pill">RGB LSB</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="security-note">
            <strong>Security note</strong><br>
            This is an educational prototype, not a production secure-messaging
            system. The AES key must be shared through a separate secure channel.
            LSB steganography can be detected by statistical analysis, and image
            transformations may destroy the embedded payload.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    '<div class="footer">'
    '<b>StegoSeal</b> · Secure Message Encryption &amp; Image Steganography'
    '<br><br>Educational Project Demonstration'
    '<br>AES-256-GCM + RGB LSB Steganography'
    '</div>',
    unsafe_allow_html=True,
)
