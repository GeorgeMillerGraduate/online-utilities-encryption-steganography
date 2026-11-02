# Crypto Studio — compact editorial edition

Extract this ZIP into `public_html/apps/encryption-steganography/`, replacing the app files. Keep the css, js and images subfolders. Route unchanged. Refresh with Ctrl+F5 after upload.

## Interface

Three-column layout: mode and compact engraved artwork on the left; message, password and cover selection in the middle; result preview, encrypted text and downloads on the right. Both Encrypt and Decrypt use the same workspace. Password reveal toggles, character count, payload capacity, uploaded-cover preview, generated-cover reset, full-screen result preview and clear actions are included.

At 1366×768 and 1366×650 browser viewport sizes the default Encrypt workspace fits without page scrolling. Layout adapts to reduced height; phones stack the workflow and scroll normally without horizontal overflow. Expanding How it works or manually resizing a textarea can require scrolling.

## Cryptography and compatibility

The supplied CryptoEnvelope, AES and LSB implementations are unchanged. Current format: JC2/JCS2, AES-128-GCM with 128-bit authentication tag; PBKDF2-HMAC-SHA-256 with 250,000 iterations, random 16-byte salt and random 12-byte IV. The same payload is used in copied text and PNG exports. The app extracts and compares the hidden payload before enabling PNG download. Supported legacy messages still follow the supplied compatibility decoder.

A wrong password or altered authenticated message does not reveal plaintext. Legacy formats explicitly report their lack of authenticity checking. Passwords, images and messages stay in the browser; the app has no upload endpoint. It does not save passwords or messages to browser storage.

Use HTTPS on your website, or http://localhost for local preview. Web Crypto is not available on arbitrary insecure HTTP origins. Do not remove the secure-context check or replace Web Crypto with an insecure fallback.

## Covers and PNGs

The default original navy/copper artwork is rasterised to an 800×500 carrier. An uploaded image retains its pixel dimensions; transparency is flattened onto white before hiding data. The downloaded PNG is generated from the actual encoded pixel data, not a decorative preview. Keep the original downloaded PNG: editing, resizing, recompression, social-site processing or JPEG conversion can destroy hidden data. Text export remains available if an uploaded image is too small for the payload.

## Verification

Run `node tests/roundtrip.cjs`. Tests cover Unicode text round trips, random salt/IV uniqueness, wrong-password rejection, tamper rejection, LSB payload recovery, carrier immutability, alpha retention, too-small-image rejection and empty-message validation. The unchanged crypto core is exercised with Node Web Crypto.

Browser checks covered mode switching, PNG upload with successful extraction of an actual encoded 88-byte payload, metadata/status behaviour, desktop/phone layout and the HTTPS/localhost requirement message. The remote HTTP preview does not expose Web Crypto, so complete browser encryption/decryption and PNG export were not exercised there; cryptographic round trips were validated separately as described above. No claim of an independent security audit is made.

Local preview: `python3 -m http.server 8080`, then open http://localhost:8080/ . No build or external runtime dependency required.
