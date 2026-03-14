# taskpane

## QuantumMail

{% stepper %}
{% step %}
### Login

Server Base

Org Id

Username

Password

Login

This uses your existing org username/password flow (no changes).
{% endstep %}

{% step %}
### Authentication state

Logged in

Logout
{% endstep %}

{% step %}
### Recipients

Recipients (only these users can decrypt)

Login to load org users.

Reload Users
{% endstep %}

{% step %}
### Attachments

Attachments (MVP: pick files here)

Selected: 0
{% endstep %}

{% step %}
### Encrypt & Insert

Encrypt & Insert Link

Reads the current email body, encrypts it + selected files, uploads ciphertext, then inserts the link.
{% endstep %}

{% step %}
### Status

Status

Ready.
{% endstep %}
{% endstepper %}
