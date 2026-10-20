# StegoSeal

StegoSeal is an educational Python web app for encrypting a short text message with AES-256-GCM and hiding the resulting authenticated ciphertext in RGB PNG pixel-channel least significant bits (LSBs).

## Run on Windows

1. Install Python 3.10 or newer.
2. Open PowerShell in this folder.
3. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies and start Streamlit:

   ```powershell
   python -m pip install -r requirements.txt
   python -m streamlit run app.py
   ```

The app opens in a browser. Generate a new key in the Hide tab, save it separately, download the output PNG, and use both in the Extract tab.

## Run the checks

```powershell
python -m unittest discover -s tests -v
```

## Design notes

- AES-GCM uses a fresh 96-bit nonce for each message. The envelope stores a version marker, nonce, and ciphertext plus the 128-bit authentication tag.
- The frame stores a marker and a four-byte payload length before the encrypted envelope.
- Each payload bit replaces one RGB channel's least significant bit. Payloads that exceed image capacity are rejected before embedding.
- Keep the output as PNG. JPEG, resizing, color transformations, and other edits can change LSBs.
- This is a classroom prototype, not production secure messaging. The app displays the key to the sender and does not solve secure key delivery or steganalysis.

## Evaluation ideas

Use several PNG sizes and message lengths. Record capacity, changed channel count, MSE, and PSNR. Verify correct recovery, wrong-key rejection, tampering rejection, and too-small-image handling. Report the machine and software versions for repeatability.
