# README

## What it does

* Login with orgId/username/password to get a JWT
* Encrypt selected text in Gmail compose:
  * Fetch active key version + key material
  * AES-GCM encrypt locally (WebCrypto)
  * POST ciphertext to backend (Model B)
  * Replace selection with share link `/m/<id>`
* Decrypt a link (paste into popup):
  * Fetch message by id
  * Fetch key by keyVersion
  * Decrypt locally

## Setup

{% stepper %}
{% step %}
### Load unpacked in Chrome

* chrome://extensions -> Developer mode -> Load unpacked -> select this folder
{% endstep %}

{% step %}
### Configure popup

* API Base: [https://quantummail-v2.onrender.com](https://quantummail-v2.onrender.com/)
* Org ID: (your Org)
{% endstep %}

{% step %}
### Backend prep

* use your Admin Creds which are requested on the website
{% endstep %}

{% step %}
### Login

* Login in the extension with that Creds which register a Public key.
{% endstep %}
{% endstepper %}

## Notes

* Encryption works for Gmail, Outlook.
