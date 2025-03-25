import json
import os
import time
import logging
import ldap3
import ssl  # Add this import
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPOperationResult
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import string
import secrets
from datetime import datetime

# Charger la configuration depuis un fichier JSON
with open('config.json') as f:
    config = json.load(f)

# Configuration du logging
logging.basicConfig(
    filename=config['log']['file'],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_ldap_connection():
    """Établit une connexion LDAP sécurisée avec retries."""
    max_retries = 3
    retry_delay = 5  # secondes
    
    for attempt in range(max_retries):
        try:
            # Configuration du serveur avec SSL/TLS
            server = Server(
                config['ldap']['server'],
                use_ssl=False,  # Changed to False as we'll use START_TLS instead
                port=389,       # Standard LDAP port
                connect_timeout=30,
                get_info=ALL
            )
            
            logging.info(f"Connecting to LDAP server: {config['ldap']['server']}")
            conn = Connection(
                server,
                user=config['ldap']['username'],
                password=config['ldap']['password'],
                authentication=NTLM,
                auto_bind=False,  # Changed to False to handle binding manually
                receive_timeout=60
            )
            
            # Establish connection and start TLS
            if not conn.bind():
                logging.error(f"Failed to bind to LDAP server: {conn.result}")
                return None
                
            # Start TLS for secure communication
            conn.start_tls()
            
            if conn.bound:
                logging.info("Successfully connected to LDAP server.")
                return conn
            else:
                logging.error(f"Failed to bind to LDAP server: {conn.result}")
                
        except LDAPOperationResult as e:
            if attempt < max_retries - 1:
                logging.warning(f"LDAP connection attempt {attempt + 1} failed: {str(e)}. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logging.error(f"Failed to connect to LDAP server after {max_retries} attempts: {str(e)}")
                raise
    
    return None

def is_user_admin(conn, user_dn):
    """Vérifie si un utilisateur est un administrateur."""
    conn.search(config['search_base'], f'(member={user_dn})', attributes=['cn'])
    return any('admin' in entry.cn.lower() for entry in conn.entries)

def is_user_in_vip_group(conn, user_dn):
    """Vérifie si un utilisateur appartient au groupe VIP."""
    conn.search(config['search_base'], f'(member={user_dn})', attributes=['cn'])
    return any(entry.dn.lower() == config['ldap']['vipGroup'].lower() for entry in conn.entries)

def find_user_dn(conn, sam_account_name, search_base):
    """Recherche le DN d'un utilisateur en fonction de son samAccountName."""
    conn.search(search_base, f'(samAccountName={sam_account_name})', attributes=['distinguishedName'])
    if conn.entries:
        return conn.entries[0].distinguishedName.value
    logging.error(f"User {sam_account_name} not found in the directory.")
    return None

def process_json_file(file_path, total_files):
    """Traite un fichier JSON pour réinitialiser le mot de passe."""
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except Exception as e:
        logging.error(f"Error reading JSON file {file_path}: {e}")
        return

    file_date = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"Processing file: {file_path}, File date: {file_date}, Total files to process: {total_files}")

    sponsor_samAccountName = data.get('samAccountName', 'Unknown Sponsor')
    user_samAccountName = data.get('user_samAccountName', 'Unknown User')
    sponsor_email = data.get('email', 'Unknown Email')

    logging.info(f"Sponsor: {sponsor_email} ({sponsor_samAccountName}), Account to reset: {user_samAccountName}")

    if sponsor_samAccountName.lower() == user_samAccountName.lower():
        logging.error(f"Self-reset attempt detected: {sponsor_samAccountName} trying to reset their own password. Request ignored.")
        send_rejection_email(sponsor_email, user_samAccountName)
        move_processed_file(file_path)
        return

    conn = get_ldap_connection()
    if not conn:
        return

    user_dn = find_user_dn(conn, user_samAccountName, config['search_base'])
    if not user_dn:
        logging.error(f"Failed to locate user {user_samAccountName} in the directory.")
        return

    logging.info(f"Attempting to reset password for user DN: {user_dn}")

    if is_user_admin(conn, user_dn):
        logging.info(f"User {user_samAccountName} is an admin. Skipping password reset.")
        return

    if is_user_in_vip_group(conn, user_dn):
        logging.info(f"User {user_samAccountName} is in VIP group. Skipping password reset.")
        return

    new_password = generate_password(user_samAccountName)
    logging.info(f"User {user_samAccountName} Reset New Password : {new_password}")

    try:
        if not config['debug_mode']:
            logging.info(f"Attempting to modify password for user DN: {user_dn}")
            # Encoder le mot de passe au format attendu par AD
            password_value = f'"{new_password}"'.encode('utf-16-le')
            
            # Utiliser la modification directe plutôt que l'extension microsoft
            modify_password = {
                'unicodePwd': [(MODIFY_REPLACE, [password_value])]
            }

            # Log the LDAP modify request
            logging.info(f"LDAP modify request: DN={user_dn}, changes={modify_password}")

            conn.modify(user_dn, modify_password)

            # Log the result of the password modification attempt
            logging.info(f"Password modification result: {conn.result}")
            
            if conn.result['result'] == 0:
                logging.info(f"Password successfully reset for {user_samAccountName}")
                send_notification_email(user_samAccountName, new_password, sponsor_email)
                send_notification_email(user_samAccountName, new_password, config['itServiceEmail'])
                move_processed_file(file_path)
                conn.modify(user_dn, {'pwdLastSet': (MODIFY_REPLACE, [0])})
            else:
                logging.error(f"Failed to reset password for {user_samAccountName}: {conn.result['description']} (Result code: {conn.result['result']})")

    except LDAPException as e:
        logging.error(f"LDAP Error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def generate_password(username):
    """Génère un mot de passe sécurisé."""
    length = 12
    all_characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"

    while True:
        password = ''.join(secrets.choice(all_characters) for _ in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password) and
            username.lower() not in password.lower()):
            return password

def send_notification_email(username, new_password, recipient_email):
    """Envoie un e-mail de notification HTML après la réinitialisation du mot de passe."""
    escaped_password = new_password.replace('<', '&lt;').replace('>', '&gt;')

    html_content = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            .password-container {{
                background-color: #f5f5f5;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
                border: 1px solid #ddd;
            }}
            .password {{
                font-family: 'Courier New', monospace;
                font-size: 24px;
                letter-spacing: 2px;
                color: #333;
                background-color: white;
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 3px;
                word-break: break-all;
            }}
            .highlight {{
                color: #0066cc;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <p>The password for user <strong>{username}</strong> has been reset.</p>
        <div class="password-container">
            <p>New password:</p>
            <div class="password">{escaped_password}</div>
        </div>
        <p><em>Note: For security reasons, please change this password at your first login.</em></p>
    </body>
    </html>
    """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Password Reset Notification'
    msg['From'] = config['smtp']['fromAddress']
    msg['To'] = recipient_email

    text_part = MIMEText(f"The password for {username} has been reset to: {new_password}", 'plain')
    html_part = MIMEText(html_content, 'html')

    msg.attach(text_part)
    msg.attach(html_part)

    try:
        logging.info(f"Connecting to SMTP server: {config['smtp']['server']}:{config['smtp']['port']}")
        server = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'])
        if config['smtp']['use_tls']:
            server.starttls()
        logging.info(f"Sending email to: {recipient_email}")
        server.sendmail(msg['From'], [recipient_email], msg.as_string())
        logging.info("Notification email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
    finally:
        server.quit()

def send_rejection_email(sponsor_email, user_samAccountName):
    """Envoie un e-mail de notification de rejet de la demande."""
    msg = MIMEText(f"Your password reset request for {user_samAccountName} has been rejected because you cannot reset your own password. Please contact IT Service Desk for assistance.")
    msg['Subject'] = 'Password Reset Request Rejected'
    msg['From'] = config['smtp']['fromAddress']
    msg['To'] = sponsor_email

    try:
        logging.info(f"Connecting to SMTP server: {config['smtp']['server']}:{config['smtp']['port']}")
        server = smtplib.SMTP(config['smtp']['server'], config['smtp']['port'])
        if config['smtp']['use_tls']:
            server.starttls()
        logging.info(f"Sending rejection email to: {sponsor_email}")
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        logging.info("Rejection notification email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send rejection email: {e}")
    finally:
        server.quit()

def move_processed_file(file_path):
    """Déplace le fichier traité vers un répertoire de sauvegarde."""
    processed_dir = config['processed']['path']
    os.makedirs(processed_dir, exist_ok=True)
    os.rename(file_path, os.path.join(processed_dir, os.path.basename(file_path)))

def main():
    """Boucle principale du service."""
    json_dir = config['share']['path']

    while True:
        files_to_process = [f for f in os.listdir(json_dir) if f.endswith('.json')]
        total_files = len(files_to_process)
        logging.info(f"Total files to process in this scan: {total_files}")

        for filename in files_to_process:
            file_path = os.path.join(json_dir, filename)
            process_json_file(file_path, total_files)

        time.sleep(config['scan_interval'])

if __name__ == '__main__':
    main()
