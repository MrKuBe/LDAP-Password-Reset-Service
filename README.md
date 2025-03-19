# LDAP-Password-Reset-Service
Automates the process of resetting user passwords by monitoring a directory for JSON files containing reset requests.

**Key Features:**

**LDAP Integration**: Connects to an LDAP server using the service account credentials to perform password resets.
**Password Generation**: Generates secure passwords that meet specific criteria (12 characters, including at least 3 out of 4 character types: uppercase, lowercase, digits, special characters, and excluding the user's name).
**Email Notifications**: Sends email notifications to the IT service and the user after a password reset.
**File Management**: Processes each JSON file once and moves it to a processed directory to avoid reprocessing.
**Security**: Ensures sensitive information is handled securely, using environment variables or secure secrets for credentials.

**Deployment**: Installed as a Windows service, managed via services.msc, and runs continuously to check for new requests.

This service enhances security and efficiency by automating password resets while ensuring compliance with password policies.
