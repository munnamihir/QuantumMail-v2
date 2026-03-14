# compose

Encrypt message + attachments in-browser. Server stores ciphertext-only. Share a secure link.

Message

Mode

{% tabs %}
{% tab title="PQC (ML-KEM-768)" %}
PQC: encrypt to recipient public key.

Recipient Public Key (base64)

Generate keys via `/portal/keygen.html`.
{% endtab %}

{% tab title="Passphrase" %}
Passphrase: encrypt with PBKDF2-derived key.

Passphrase
{% endtab %}
{% endtabs %}

Attachments (MVP)

{% hint style="info" %}
MVP sends encrypted attachments inside JSON — keep files small (few MB total).
{% endhint %}

Encrypt & Generate Link

Copy Link

Clear

Result

—
