import json
import os
import time
import logging
import ldap3
from ldap3 import Server, Connection, ALL, NTLM
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
    """Établit une connexion LDAP sécurisée en utilisant les informations d'identification fournies."""
    server = Server(config['ldap']['server'], use_ssl=True, get_info=ALL)

    logging.info(f"Connecting to LDAP server: {config['ldap']['server']}")
    logging.info(f"Using domain: {config['ldap']['domain']}")

    try:
        conn = Connection(server,
                          user=config['ldap']['username'],
                          password=config['ldap']['password'],
                          authentication=NTLM)
        if not conn.bind():
            logging.error(f"Unable to connect to LDAP server. Bind result: {conn.result}")
            return None
        logging.info("Successfully connected to LDAP server.")
        return conn
    except Exception as e:
        logging.error(f"Error connecting to LDAP server: {e}")
        return None

def is_user_admin(conn, user_dn):
    """Vérifie si un utilisateur est un administrateur."""
    conn.search(config['search_base'], f'(member={user_dn})', attributes=['cn'])
    if conn.entries:
        for entry in conn.entries:
            if 'admin' in entry.cn.lower():
                return True
    return False

def is_user_in_vip_group(conn, user_dn):
    """Vérifie si un utilisateur appartient au groupe VIP."""
    conn.search(config['search_base'], f'(member={user_dn})', attributes=['cn'])
    if conn.entries:
        for entry in conn.entries:
            if entry.dn.lower() == config['ldap']['vipGroup'].lower():
                return True
    return False

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

    # Utilisez les clés correctes du fichier JSON
    sponsor_samAccountName = data.get('samAccountName', 'Unknown Sponsor')
    user_samAccountName = data.get('user_samAccountName', 'Unknown User')
    sponsor_email = data.get('email', 'Unknown Email')

    logging.info(f"Sponsor: {sponsor_email} ({sponsor_samAccountName}), Account to reset: {user_samAccountName}")

    # Vérifier si le demandeur essaie de réinitialiser son propre mot de passe
    if sponsor_samAccountName.lower() == user_samAccountName.lower():
        logging.error(f"Self-reset attempt detected: {sponsor_samAccountName} trying to reset their own password. Request ignored.")
        send_rejection_email(sponsor_email, user_samAccountName)
        move_processed_file(file_path)
        return

    conn = get_ldap_connection()
    if not conn:
        return

    user_dn = f"CN={user_samAccountName},{config['search_base']}"

    # Vérifier si l'utilisateur est un administrateur ou dans le groupe VIP
    if is_user_admin(conn, user_dn):
        logging.info(f"User {user_samAccountName} is an admin. Skipping password reset.")
        return

    if is_user_in_vip_group(conn, user_dn):
        logging.info(f"User {user_samAccountName} is in VIP group. Skipping password reset.")
        return

    new_password = generate_password(user_samAccountName)

    if config['debug_mode']:
        logging.info(f"DEBUG MODE: Simulating password reset for {user_samAccountName}. New password would be: {new_password}")
        # Envoyer les deux emails séparément
        send_notification_email(user_samAccountName, new_password, sponsor_email)
        send_notification_email(user_samAccountName, new_password, config['itServiceEmail'])
        move_processed_file(file_path)
    else:
        try:
            conn.extend.microsoft.modify_password(user_dn, new_password)

            if conn.result['result'] == 0:
                logging.info(f"Password successfully reset for {user_samAccountName}")
                # Envoyer les deux emails séparément
                send_notification_email(user_samAccountName, new_password, sponsor_email)
                send_notification_email(user_samAccountName, new_password, config['itServiceEmail'])
                move_processed_file(file_path)
                conn.modify(user_dn, {'pwdLastSet': (ldap3.MODIFY_REPLACE, [0])})
            else:
                logging.error(f"Failed to reset password for {user_samAccountName}: {conn.result['description']}")
        except Exception as e:
            logging.error(f"Error resetting password: {e}")

def generate_password(username):
    """Génère un mot de passe sécurisé selon les spécifications."""
    length = 12
    all_characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"

    while True:
        password = ''.join(secrets.choice(all_characters) for _ in range(length))

        # Vérifier les caractéristiques du mot de passe
        if (any(c.islower() for c in password) +
            any(c.isupper() for c in password) +
            any(c.isdigit() for c in password) +
            any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password) >= 3 and
            username.lower() not in password.lower()):
            return password

def send_notification_email(username, new_password, recipient_email):
    """Envoie un e-mail de notification HTML après la réinitialisation du mot de passe."""
    # Échapper les caractères spéciaux HTML dans le mot de passe
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

    # Ajouter une version texte pour les clients qui ne supportent pas HTML
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

        time.sleep(config['scan_interval'])  # Attendre selon l'intervalle défini dans le fichier de configuration

if __name__ == '__main__':
    main()
