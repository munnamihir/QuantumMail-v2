# setup admin

Verify your email first, then set your password to activate your admin account.

{% stepper %}
{% step %}
### Verify your email

We’ll send a 6-digit code to confirm you own this inbox.

Fields / actions:

* Org ID
* Email (from request)
* Verify (button)

Verify modal / flow:

* Title: QuantumMail Verification
* Prompt: We’ll send a 6-digit code to confirm you own this inbox.
* Email
* Send Code (button)
* Enter code
* Verify (button)
* Close (button)
{% endstep %}

{% step %}
### Activate account

After email verification, set your password to activate your admin account.

Fields / actions:

* New Password (>= 12 chars)
* Activate (button)

Status / labels:

* Activate
* 🚗
{% endstep %}
{% endstepper %}
