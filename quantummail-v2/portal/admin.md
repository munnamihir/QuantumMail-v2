# admin

Users, keys, access, audit, analytics — enterprise-ready.

{% stepper %}
{% step %}
### Create Admin

First-time setup only. Creates an **Admin** user for an org with custom credentials.

Fields:

* Org Id
* Admin Username
* Admin Email
* Admin Password

Action:

* Create Admin
{% endstep %}

{% step %}
### Users & Key Health

Create users, refresh list, remove users, and clear public keys (forces re-register on next login).

Fields:

* New Username
* Email
* New Password
* Role

Actions:

* Create User
* Refresh

Note: All actions are audited

Users table:

| User           | Role | Status | Key Health | Last Login | Actions |
| -------------- | ---- | ------ | ---------- | ---------- | ------- |
| Loading users… |      |        |            |            |         |
{% endstep %}
{% endstepper %}

## Signed in as

| Org Name | — |
| -------- | - |
| Org Id   | — |
| Username | — |

### Change Password

Fields:

* Current Password
* New Password
* Confirm New Password

Action:

* Update Password
