# LDAP Password Reset Service
A Python service that automates Active Directory password resets by monitoring a shared folder for JSON request files.

## Features

### LDAP Integration:
- Connects to Active Directory using service account credentials
- Supports START_TLS for secure communication
- Validates user permissions before reset

### Password Management:
    Generates secure 12-character passwords
    Enforces complexity requirements:
        Uppercase letters
        Lowercase letters
        Numbers
        Special characters
        Excludes username from password

### Email Notifications:
    HTML-formatted emails with password information
    Notifications sent to:
        Request sponsor
        IT Service desk
    Configurable SMTP settings

### Security:
    Secure LDAP communication via START_TLS
    Password complexity enforcement
    VIP user protection
    Admin account protection
    Self-reset prevention

## Prerequisites

### System Requirements
  
+ Windows Server/Desktop
+ Python 3.x
+ Network access to:
    Active Directory server (LDAP 389)
    SMTP server
    Network shares

### Required Python Packages

    pip install ldap3

### Active Directory Requirements

+ Service account with permissions for:
    Password resets
    User attribute modifications    
    AD queries

## Configuration
Create a config.json file:

    {
        "ldap": {
            "server": "ldap://your-ad-server",
            "username": "service_account@domain.com",
            "password": "service_account_password",
            "search_base": "DC=domain,DC=com",
            "vipGroup": "CN=VIP,DC=domain,DC=com"
        },
        "smtp": {
            "server": "smtp.domain.com",
            "port": 25,
            "fromAddress": "noreply@domain.com",
            "use_tls": true
        },
        "share": {
            "path": "\\\\server\\share\\requests"
        },
        "processed": {
            "path": "\\\\server\\share\\processed"
        },
        "log": {
            "file": "password-reset-service.log"
        },
        "scan_interval": 60,
        "debug_mode": false,
        "itServiceEmail": "it@domain.com"
    }

## Usage

### Password Reset Request Format

Place a JSON file in the monitored directory:

{
    "samAccountName": "sponsor_username",
    "user_samAccountName": "user_to_reset",
    "email": "sponsor@domain.com"
}

### Running the Service

python main.py

### Service Behavior
1. Monitors shared folder for JSON files
2. Validates request format and permissions
3. Generates secure password
4. Resets user password in AD
5. Sends notification emails
6. Moves processed file to archive

##  Logging

The service logs all operations to the configured log file, including:

File processing
LDAP operations
Password resets
Email notifications
Errors and warnings

## Security Considerations

- Uses START_TLS for LDAP communication
- Prevents self-password resets
- Protects admin and VIP accounts
- Moves processed files to secure location
- Logs all operations for audit

## Error Handling

- Retries LDAP connections
- Validates JSON file format
- Checks user permissions
- Reports errors via logging
- Maintains processed files

## Support

For issues or questions, contact your system administrator or open an issue in the repository.

## License

MIT License

Copyright (c) 2025 Bertrand Kuzbinski

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.