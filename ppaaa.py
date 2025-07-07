#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import smtplib
import os
import time
import threading
import concurrent.futures
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
import socket
from typing import List, Tuple, Optional, Dict
import sys
import re

# Codes couleurs ANSI
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Couleurs principales
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Couleurs de fond
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'
    BG_MAGENTA = '\033[105m'
    BG_CYAN = '\033[106m'
    
    # Couleurs personnalisées
    ORANGE = '\033[38;5;208m'
    PURPLE = '\033[38;5;135m'
    LIME = '\033[38;5;154m'
    PINK = '\033[38;5;213m'

class ProgressBar:
    def __init__(self, total: int, length: int = 50):
        self.total = total
        self.length = length
        self.current = 0
        
    def update(self, current: int):
        self.current = current
        percent = (current / self.total) * 100
        filled = int(self.length * current // self.total)
        bar = f"{Colors.GREEN}{'█' * filled}{Colors.DIM}{'░' * (self.length - filled)}{Colors.RESET}"
        print(f"\r  {Colors.CYAN}[{bar}{Colors.CYAN}]{Colors.RESET} {Colors.BOLD}{percent:6.1f}%{Colors.RESET} ({current}/{self.total})", end='', flush=True)
        
    def finish(self):
        print()

class SMTPDetector:
    """Détecteur automatique de serveurs SMTP"""
    
    # Base de données des serveurs SMTP communs
    SMTP_DATABASE = {
        # Gmail et Google Workspace
        'gmail.com': [('smtp.gmail.com', 587), ('smtp.gmail.com', 465)],
        'googlemail.com': [('smtp.gmail.com', 587), ('smtp.gmail.com', 465)],
        
        # Outlook/Hotmail/Live
        'outlook.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
        'hotmail.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
        'live.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
        'msn.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
        
        # Yahoo
        'yahoo.com': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
        'yahoo.fr': [('smtp.mail.yahoo.fr', 587), ('smtp.mail.yahoo.fr', 465)],
        'yahoo.co.uk': [('smtp.mail.yahoo.co.uk', 587), ('smtp.mail.yahoo.co.uk', 465)],
        'ymail.com': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
        'rocketmail.com': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
        
        # AOL
        'aol.com': [('smtp.aol.com', 587), ('smtp.aol.com', 465)],
        'aim.com': [('smtp.aol.com', 587), ('smtp.aol.com', 465)],
        
        # iCloud
        'icloud.com': [('smtp.mail.me.com', 587), ('smtp.mail.me.com', 465)],
        'me.com': [('smtp.mail.me.com', 587), ('smtp.mail.me.com', 465)],
        'mac.com': [('smtp.mail.me.com', 587), ('smtp.mail.me.com', 465)],
        
        # Zoho
        'zoho.com': [('smtp.zoho.com', 587), ('smtp.zoho.com', 465)],
        'zohomail.com': [('smtp.zoho.com', 587), ('smtp.zoho.com', 465)],
        
        # FastMail
        'fastmail.com': [('smtp.fastmail.com', 587), ('smtp.fastmail.com', 465)],
        'fastmail.fm': [('smtp.fastmail.com', 587), ('smtp.fastmail.com', 465)],
        
        # ProtonMail
        'protonmail.com': [('127.0.0.1', 1025)],  # Nécessite ProtonMail Bridge
        'proton.me': [('127.0.0.1', 1025)],
        
        # GMX
        'gmx.com': [('mail.gmx.com', 587), ('mail.gmx.com', 465)],
        'gmx.net': [('mail.gmx.net', 587), ('mail.gmx.net', 465)],
        'gmx.de': [('mail.gmx.net', 587), ('mail.gmx.net', 465)],
        
        # Mail.ru
        'mail.ru': [('smtp.mail.ru', 587), ('smtp.mail.ru', 465)],
        'inbox.ru': [('smtp.mail.ru', 587), ('smtp.mail.ru', 465)],
        'list.ru': [('smtp.mail.ru', 587), ('smtp.mail.ru', 465)],
        
        # Yandex
        'yandex.com': [('smtp.yandex.com', 587), ('smtp.yandex.com', 465)],
        'yandex.ru': [('smtp.yandex.ru', 587), ('smtp.yandex.ru', 465)],
        
        # Providers français
        'laposte.net': [('smtp.laposte.net', 587), ('smtp.laposte.net', 465)],
        'orange.fr': [('smtp.orange.fr', 587), ('smtp.orange.fr', 465)],
        'wanadoo.fr': [('smtp.orange.fr', 587), ('smtp.orange.fr', 465)],
        'free.fr': [('smtp.free.fr', 587), ('smtp.free.fr', 465)],
        'sfr.fr': [('smtp.sfr.fr', 587), ('smtp.sfr.fr', 465)],
        'bbox.fr': [('smtp.bbox.fr', 587), ('smtp.bbox.fr', 465)],
        'alice.fr': [('smtp.alice.fr', 587), ('smtp.alice.fr', 465)],
        
        # Providers allemands
        'web.de': [('smtp.web.de', 587), ('smtp.web.de', 465)],
        't-online.de': [('securesmtp.t-online.de', 587), ('securesmtp.t-online.de', 465)],
        
        # Providers italiens
        'libero.it': [('smtp.libero.it', 587), ('smtp.libero.it', 465)],
        'virgilio.it': [('smtp.virgilio.it', 587), ('smtp.virgilio.it', 465)],
        
        # Providers espagnols
        'terra.es': [('smtp.terra.es', 587), ('smtp.terra.es', 465)],
        
        # Autres providers populaires
        'rediffmail.com': [('smtp.rediffmail.com', 587), ('smtp.rediffmail.com', 465)],
        'qq.com': [('smtp.qq.com', 587), ('smtp.qq.com', 465)],
        '163.com': [('smtp.163.com', 587), ('smtp.163.com', 465)],
        '126.com': [('smtp.126.com', 587), ('smtp.126.com', 465)],
        'sina.com': [('smtp.sina.com', 587), ('smtp.sina.com', 465)],
    }
    
    @staticmethod
    def get_domain_from_email(email: str) -> str:
        """Extrait le domaine d'une adresse email"""
        return email.split('@')[1].lower() if '@' in email else ''
    
    @staticmethod
    def generate_smtp_candidates(domain: str) -> List[Tuple[str, int]]:
        """Génère une liste de candidats SMTP pour un domaine"""
        candidates = []
        
        # Vérifier la base de données
        if domain in SMTPDetector.SMTP_DATABASE:
            candidates.extend(SMTPDetector.SMTP_DATABASE[domain])
        
        # Générer des candidats automatiques
        smtp_patterns = [
            f'smtp.{domain}',
            f'mail.{domain}',
            f'smtp.mail.{domain}',
            f'secure.{domain}',
            f'ssl.{domain}',
            f'outgoing.{domain}',
            f'mx.{domain}',
            f'mx1.{domain}',
            f'mx2.{domain}',
            f'mailout.{domain}',
            f'send.{domain}',
            f'out.{domain}',
            f'relay.{domain}',
            f'mta.{domain}',
            f'smtpauth.{domain}',
            f'smtpout.{domain}',
            f'mailserver.{domain}',
            f'email.{domain}',
            domain  # Parfois le domaine principal fait office de SMTP
        ]
        
        # Ports communs
        ports = [587, 465, 25, 2525, 2587]
        
        # Combiner patterns et ports
        for pattern in smtp_patterns:
            for port in ports:
                if (pattern, port) not in candidates:
                    candidates.append((pattern, port))
        
        return candidates
    
    @staticmethod
    def test_smtp_fast(smtp_server: str, port: int, email: str, password: str, timeout: int = 5) -> Tuple[bool, str]:
        """Test rapide d'une configuration SMTP"""
        try:
            # Configuration du timeout
            socket.setdefaulttimeout(timeout)
            
            # Connexion selon le port
            if port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port)
            else:
                server = smtplib.SMTP(smtp_server, port)
                if port == 587:
                    server.starttls()
            
            # Test d'authentification
            server.login(email, password)
            server.quit()
            
            return True, "OK"
            
        except smtplib.SMTPAuthenticationError:
            return False, "Auth"
        except smtplib.SMTPConnectError:
            return False, "Connect"
        except smtplib.SMTPServerDisconnected:
            return False, "Disconnected"
        except socket.timeout:
            return False, "Timeout"
        except socket.gaierror:
            return False, "DNS"
        except Exception as e:
            return False, f"Error: {str(e)[:20]}"
        finally:
            socket.setdefaulttimeout(None)
    
    @staticmethod
    def detect_smtp_for_email(email: str, password: str, max_workers: int = 10) -> Optional[Tuple[str, int]]:
        """Détecte automatiquement le serveur SMTP pour un email donné"""
        domain = SMTPDetector.get_domain_from_email(email)
        if not domain:
            return None
        
        candidates = SMTPDetector.generate_smtp_candidates(domain)
        
        # Test parallèle des candidats
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Soumettre tous les tests
            future_to_candidate = {
                executor.submit(SMTPDetector.test_smtp_fast, smtp_server, port, email, password): (smtp_server, port)
                for smtp_server, port in candidates
            }
            
            # Retourner le premier qui fonctionne
            for future in concurrent.futures.as_completed(future_to_candidate):
                smtp_server, port = future_to_candidate[future]
                try:
                    is_working, message = future.result()
                    if is_working:
                        return (smtp_server, port)
                except Exception:
                    continue
        
        return None

class SMTPMailer:
    def __init__(self):
        self.working_smtps = []
        self.test_email = ""
        self.sender_name = ""
        self.subject = ""
        self.html_content = ""
        self.recipients = []
        self.email_delay = 0.01  # Délai réduit par défaut
        self.max_workers = 20    # Nombre de threads pour les tests
        self.stats = {
            'total_sent': 0,
            'total_failed': 0,
            'smtp_used': 0,
            'start_time': None,
            'end_time': None,
            'detection_time': None
        }
        
    def print_header(self, title: str, color: str = Colors.CYAN):
        """Affiche un en-tête stylisé"""
        width = 80
        border = '═' * width
        print(f"\n{color}{border}{Colors.RESET}")
        print(f"{color}║{Colors.BOLD}{title.center(width-2)}{Colors.RESET}{color}║{Colors.RESET}")
        print(f"{color}{border}{Colors.RESET}\n")
    
    def print_section(self, title: str, color: str = Colors.BLUE):
        """Affiche une section stylisée"""
        print(f"\n{color}{'─' * 60}{Colors.RESET}")
        print(f"{color}{Colors.BOLD}🔹 {title}{Colors.RESET}")
        print(f"{color}{'─' * 60}{Colors.RESET}")
    
    def print_success(self, message: str):
        """Affiche un message de succès"""
        print(f"{Colors.GREEN}✅ {message}{Colors.RESET}")
    
    def print_error(self, message: str):
        """Affiche un message d'erreur"""
        print(f"{Colors.RED}❌ {message}{Colors.RESET}")
    
    def print_warning(self, message: str):
        """Affiche un avertissement"""
        print(f"{Colors.ORANGE}⚠️  {message}{Colors.RESET}")
    
    def print_info(self, message: str):
        """Affiche une information"""
        print(f"{Colors.CYAN}ℹ️  {message}{Colors.RESET}")
    
    def validate_email(self, email: str) -> bool:
        """Valide le format d'un email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def validate_file_path(self, path: str, file_type: str) -> bool:
        """Valide l'existence et l'accessibilité d'un fichier"""
        if not path.strip():
            self.print_error(f"Chemin {file_type} vide")
            return False
        
        if not os.path.exists(path):
            self.print_error(f"Fichier {file_type} introuvable: {path}")
            return False
        
        if not os.access(path, os.R_OK):
            self.print_error(f"Fichier {file_type} non lisible: {path}")
            return False
        
        return True
    
    def load_email_credentials(self, file_path: str) -> List[Tuple[str, str]]:
        """Charge les identifiants email depuis un fichier au format email:password"""
        credentials = []
        invalid_lines = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            self.print_info(f"Analyse de {len(lines)} lignes dans le fichier credentials...")
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Ignorer les lignes vides et commentaires
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                try:
                    # Format: email:password
                    if ':' not in line:
                        self.print_warning(f"Ligne {line_num}: Format incorrect (attendu: email:password)")
                        invalid_lines += 1
                        continue
                    
                    parts = line.split(':', 1)  # Split seulement sur le premier ':'
                    email = parts[0].strip()
                    password = parts[1].strip()
                    
                    # Validation de l'email
                    if not self.validate_email(email):
                        self.print_warning(f"Ligne {line_num}: Email invalide '{email}'")
                        invalid_lines += 1
                        continue
                    
                    # Validation du mot de passe
                    if not password:
                        self.print_warning(f"Ligne {line_num}: Mot de passe vide")
                        invalid_lines += 1
                        continue
                    
                    credentials.append((email, password))
                    
                except Exception as e:
                    self.print_warning(f"Ligne {line_num}: Erreur de traitement - {e}")
                    invalid_lines += 1
                    
        except FileNotFoundError:
            self.print_error(f"Fichier credentials non trouvé: {file_path}")
            return []
        except PermissionError:
            self.print_error(f"Permission refusée pour lire: {file_path}")
            return []
        except Exception as e:
            self.print_error(f"Erreur lors du chargement du fichier: {e}")
            return []
        
        # Résumé du chargement
        if invalid_lines > 0:
            self.print_warning(f"{invalid_lines} ligne(s) ignorée(s)")
        
        self.print_success(f"{len(credentials)} credential(s) valide(s) chargé(s)")
        return credentials
    
    def detect_smtp_parallel(self, credentials: List[Tuple[str, str]]) -> None:
        """Détecte les serveurs SMTP en parallèle pour une liste d'emails"""
        self.print_section("DÉTECTION AUTOMATIQUE DES SERVEURS SMTP", Colors.MAGENTA)
        
        if not credentials:
            self.print_error("Aucun credential à traiter")
            return
        
        detection_start = time.time()
        progress = ProgressBar(len(credentials))
        
        self.print_info(f"Détection SMTP pour {len(credentials)} comptes avec {self.max_workers} threads...")
        
        # Fonction pour traiter un credential
        def process_credential(email_password):
            email, password = email_password
            domain = SMTPDetector.get_domain_from_email(email)
            
            # Détection du serveur SMTP
            smtp_config = SMTPDetector.detect_smtp_for_email(email, password, max_workers=5)
            
            if smtp_config:
                smtp_server, port = smtp_config
                return (smtp_server, port, email, password, True, "Détecté")
            else:
                return (None, None, email, password, False, "Échec détection")
        
        # Traitement parallèle
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_email = {
                executor.submit(process_credential, cred): cred[0] 
                for cred in credentials
            }
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_email):
                email = future_to_email[future]
                try:
                    result = future.result()
                    smtp_server, port, email, password, success, message = result
                    
                    if success:
                        self.working_smtps.append((smtp_server, port, email, password))
                        print(f"\n{Colors.GREEN}✅ {email}{Colors.RESET} -> {Colors.CYAN}{smtp_server}:{port}{Colors.RESET}")
                    else:
                        print(f"\n{Colors.RED}❌ {email}{Colors.RESET} -> {Colors.DIM}{message}{Colors.RESET}")
                    
                    completed += 1
                    progress.update(completed)
                    
                except Exception as e:
                    print(f"\n{Colors.RED}❌ {email}{Colors.RESET} -> {Colors.DIM}Erreur: {e}{Colors.RESET}")
                    completed += 1
                    progress.update(completed)
        
        progress.finish()
        
        detection_time = time.time() - detection_start
        self.stats['detection_time'] = detection_time
        
        # Résumé de la détection
        working_count = len(self.working_smtps)
        total_count = len(credentials)
        success_rate = (working_count / total_count * 100) if total_count > 0 else 0
        
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 RÉSUMÉ DE DÉTECTION:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ SMTP détectés:{Colors.RESET} {Colors.BOLD}{working_count}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Échecs:{Colors.RESET} {Colors.BOLD}{total_count - working_count}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📈 Taux de réussite:{Colors.RESET} {Colors.BOLD}{success_rate:.1f}%{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️  Temps de détection:{Colors.RESET} {Colors.BOLD}{detection_time:.1f}s{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🚀 Vitesse:{Colors.RESET} {Colors.BOLD}{total_count/detection_time:.1f} tests/s{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}")
    
    def send_test_email(self, smtp_server: str, port: int, email: str, password: str, test_recipient: str) -> Tuple[bool, str]:
        """Envoie un email de test rapide"""
        try:
            # Configuration du message de test
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.sender_name} <{email}>"
            msg['To'] = test_recipient
            msg['Subject'] = Header("🔍 Test SMTP - Vérification", 'utf-8')
            
            # Contenu HTML de test simple
            test_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px;">
                    <h2 style="color: #4CAF50;">🚀 Test SMTP Réussi</h2>
                    <p><strong>Serveur:</strong> {smtp_server}:{port}</p>
                    <p><strong>Email:</strong> {email}</p>
                    <p><strong>Timestamp:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                    <p style="color: #28a745;"><strong>✅ Serveur SMTP fonctionnel</strong></p>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(test_html, 'html', 'utf-8'))
            
            # Connexion et envoi rapide
            socket.setdefaulttimeout(10)
            
            if port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port)
            else:
                server = smtplib.SMTP(smtp_server, port)
                if port == 587:
                    server.starttls()
            
            server.login(email, password)
            server.send_message(msg)
            server.quit()
            
            return True, "Test envoyé"
            
        except Exception as e:
            return False, f"Erreur: {str(e)[:30]}"
        finally:
            socket.setdefaulttimeout(None)
    
    def load_recipients(self, file_path: str) -> List[str]:
        """Charge et valide la liste des destinataires"""
        recipients = []
        invalid_emails = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            self.print_info(f"Analyse de {len(lines)} lignes dans le fichier destinataires...")
            
            for line_num, line in enumerate(lines, 1):
                email = line.strip()
                
                # Ignorer les lignes vides et commentaires
                if not email or email.startswith('#') or email.startswith('//'):
                    continue
                
                if self.validate_email(email):
                    if email not in recipients:  # Éviter les doublons
                        recipients.append(email)
                else:
                    invalid_emails += 1
                    
        except Exception as e:
            self.print_error(f"Erreur chargement destinataires: {e}")
            return []
        
        # Résumé du chargement
        if invalid_emails > 0:
            self.print_warning(f"{invalid_emails} email(s) invalide(s) ignoré(s)")
        
        self.print_success(f"{len(recipients)} destinataire(s) valide(s) chargé(s)")
        return recipients
    
    def load_html_template(self, file_path: str) -> str:
        """Charge le template HTML"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if not content.strip():
                self.print_error("Fichier HTML vide")
                return ""
            
            size_kb = len(content.encode('utf-8')) / 1024
            self.print_success(f"Template HTML chargé ({size_kb:.1f} KB)")
            
            return content
            
        except Exception as e:
            self.print_error(f"Erreur chargement HTML: {e}")
            return ""
    
    def send_bulk_emails_fast(self) -> None:
        """Envoi rapide en masse avec threading optimisé"""
        if not self.working_smtps:
            self.print_error("Aucun serveur SMTP fonctionnel")
            return
        
        if not self.recipients:
            self.print_error("Aucun destinataire")
            return
        
        if not self.html_content:
            self.print_error("Aucun contenu HTML")
            return
        
        self.print_section("ENVOI EN MASSE RAPIDE", Colors.GREEN)
        
        # Affichage des paramètres
        print(f"{Colors.CYAN}📊 PARAMÈTRES D'ENVOI RAPIDE:{Colors.RESET}")
        print(f"  {Colors.BLUE}👥 Destinataires:{Colors.RESET} {Colors.BOLD}{len(self.recipients):,}{Colors.RESET}")
        print(f"  {Colors.BLUE}🖥️  Serveurs SMTP:{Colors.RESET} {Colors.BOLD}{len(self.working_smtps)}{Colors.RESET}")
        print(f"  {Colors.BLUE}🧵 Threads max:{Colors.RESET} {Colors.BOLD}{self.max_workers}{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️  Délai:{Colors.RESET} {Colors.BOLD}{self.email_delay}s{Colors.RESET}")
        
        self.stats['start_time'] = datetime.now()
        
        # Répartition des destinataires entre les SMTP
        recipients_per_smtp = len(self.recipients) // len(self.working_smtps)
        remainder = len(self.recipients) % len(self.working_smtps)
        
        # Fonction d'envoi par lot
        def send_batch(smtp_config, recipients_batch, batch_id):
            smtp_server, port, email, password = smtp_config
            sent_count = 0
            
            try:
                # Connexion
                socket.setdefaulttimeout(30)
                
                if port == 465:
                    server = smtplib.SMTP_SSL(smtp_server, port)
                else:
                    server = smtplib.SMTP(smtp_server, port)
                    if port == 587:
                        server.starttls()
                
                server.login(email, password)
                
                # Envoi des emails
                for recipient in recipients_batch:
                    try:
                        msg = MIMEMultipart('alternative')
                        msg['From'] = f"{self.sender_name} <{email}>"
                        msg['To'] = recipient
                        msg['Subject'] = Header(self.subject, 'utf-8')
                        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
                        
                        msg.attach(MIMEText(self.html_content, 'html', 'utf-8'))
                        
                        server.send_message(msg)
                        sent_count += 1
                        self.stats['total_sent'] += 1
                        
                        # Délai entre emails
                        if self.email_delay > 0:
                            time.sleep(self.email_delay)
                        
                    except Exception as e:
                        self.stats['total_failed'] += 1
                        print(f"\n{Colors.RED}❌ Échec envoi vers {recipient}: {str(e)[:30]}{Colors.RESET}")
                
                server.quit()
                
            except Exception as e:
                print(f"\n{Colors.RED}❌ Erreur SMTP {smtp_server}:{port} - {str(e)[:50]}{Colors.RESET}")
                self.stats['total_failed'] += len(recipients_batch) - sent_count
            finally:
                socket.setdefaulttimeout(None)
            
            return sent_count
        
        # Répartition des destinataires
        smtp_batches = []
        start_idx = 0
        
        for i, smtp_config in enumerate(self.working_smtps):
            # Calcul du nombre de destinataires pour ce SMTP
            batch_size = recipients_per_smtp + (1 if i < remainder else 0)
            end_idx = start_idx + batch_size
            
            recipients_batch = self.recipients[start_idx:end_idx]
            smtp_batches.append((smtp_config, recipients_batch, i))
            
            start_idx = end_idx
        
        # Barre de progression
        progress = ProgressBar(len(self.recipients))
        
        # Envoi parallèle
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {
                executor.submit(send_batch, smtp_config, recipients_batch, batch_id): batch_id
                for smtp_config, recipients_batch, batch_id in smtp_batches
            }
            
            completed_batches = 0
            for future in concurrent.futures.as_completed(future_to_batch):
                batch_id = future_to_batch[future]
                try:
                    batch_sent = future.result()
                    completed_batches += 1
                    progress.update(self.stats['total_sent'])
                    
                    print(f"\n{Colors.GREEN}✅ Lot {batch_id + 1}/{len(smtp_batches)} terminé: {batch_sent} envoyé(s){Colors.RESET}")
                    
                except Exception as e:
                    print(f"\n{Colors.RED}❌ Erreur lot {batch_id + 1}: {e}{Colors.RESET}")
                    completed_batches += 1
        
        progress.finish()
        
        self.stats['end_time'] = datetime.now()
        self.stats['smtp_used'] = len(self.working_smtps)
        
        # Affichage des statistiques finales
        self.print_final_stats()
    
    def print_final_stats(self):
        """Affiche les statistiques finales"""
        if not self.stats['start_time'] or not self.stats['end_time']:
            return
        
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        total_emails = self.stats['total_sent'] + self.stats['total_failed']
        success_rate = (self.stats['total_sent'] / total_emails * 100) if total_emails > 0 else 0
        speed = self.stats['total_sent'] / duration if duration > 0 else 0
        
        print(f"\n{Colors.CYAN}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}📊 STATISTIQUES FINALES D'ENVOI{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 80}{Colors.RESET}")
        
        print(f"{Colors.BOLD}🎯 RÉSULTATS:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Emails envoyés:{Colors.RESET} {Colors.BOLD}{self.stats['total_sent']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Échecs:{Colors.RESET} {Colors.BOLD}{self.stats['total_failed']:,}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📈 Taux de réussite:{Colors.RESET} {Colors.BOLD}{success_rate:.1f}%{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}⏱️  PERFORMANCE:{Colors.RESET}")
        print(f"  {Colors.BLUE}🕒 Durée totale:{Colors.RESET} {Colors.BOLD}{duration:.1f}s{Colors.RESET}")
        print(f"  {Colors.BLUE}🚀 Vitesse:{Colors.RESET} {Colors.BOLD}{speed:.1f} emails/s{Colors.RESET}")
        print(f"  {Colors.BLUE}🖥️  Serveurs utilisés:{Colors.RESET} {Colors.BOLD}{self.stats['smtp_used']}{Colors.RESET}")
        
        if self.stats['detection_time']:
            print(f"  {Colors.MAGENTA}🔍 Temps de détection:{Colors.RESET} {Colors.BOLD}{self.stats['detection_time']:.1f}s{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}{'═' * 80}{Colors.RESET}")
    
    def interactive_setup(self):
        """Configuration interactive du mailer"""
        self.print_header("🚀 AUTO SMTP MAILER - CONFIGURATION INTERACTIVE", Colors.MAGENTA)
        
        # 1. Chargement des credentials
        self.print_section("📧 CHARGEMENT DES CREDENTIALS EMAIL", Colors.BLUE)
        
        while True:
            credentials_file = input(f"{Colors.CYAN}📁 Fichier des credentials (email:password):{Colors.RESET} ").strip()
            
            if not credentials_file:
                self.print_error("Chemin requis")
                continue
            
            if not self.validate_file_path(credentials_file, "credentials"):
                continue
            
            credentials = self.load_email_credentials(credentials_file)
            if credentials:
                break
            else:
                self.print_error("Aucun credential valide trouvé")
        
        # 2. Détection automatique des SMTP
        self.detect_smtp_parallel(credentials)
        
        if not self.working_smtps:
            self.print_error("Aucun serveur SMTP fonctionnel détecté")
            return
        
        # 3. Test optionnel
        self.print_section("🧪 TEST OPTIONNEL", Colors.YELLOW)
        test_choice = input(f"{Colors.CYAN}Effectuer un test d'envoi? (o/N):{Colors.RESET} ").strip().lower()
        
        if test_choice in ['o', 'oui', 'y', 'yes']:
            while True:
                self.test_email = input(f"{Colors.CYAN}📧 Email de test:{Colors.RESET} ").strip()
                
                if not self.test_email:
                    self.print_error("Email de test requis")
                    continue
                
                if not self.validate_email(self.test_email):
                    self.print_error("Format email invalide")
                    continue
                
                # Test avec le premier SMTP disponible
                smtp_server, port, email, password = self.working_smtps[0]
                self.print_info(f"Test avec {smtp_server}:{port} ({email})")
                
                success, message = self.send_test_email(smtp_server, port, email, password, self.test_email)
                
                if success:
                    self.print_success(f"Email de test envoyé à {self.test_email}")
                    break
                else:
                    self.print_error(f"Échec du test: {message}")
                    break
        
        # 4. Configuration de l'envoi
        self.print_section("📬 CONFIGURATION DE L'ENVOI", Colors.GREEN)
        
        # Nom de l'expéditeur
        while True:
            self.sender_name = input(f"{Colors.CYAN}👤 Nom expéditeur:{Colors.RESET} ").strip()
            if self.sender_name:
                break
            self.print_error("Nom expéditeur requis")
        
        # Sujet
        while True:
            self.subject = input(f"{Colors.CYAN}📋 Sujet:{Colors.RESET} ").strip()
            if self.subject:
                break
            self.print_error("Sujet requis")
        
        # Fichier HTML
        while True:
            html_file = input(f"{Colors.CYAN}📄 Fichier HTML:{Colors.RESET} ").strip()
            
            if not html_file:
                self.print_error("Chemin fichier HTML requis")
                continue
            
            if not self.validate_file_path(html_file, "HTML"):
                continue
            
            self.html_content = self.load_html_template(html_file)
            if self.html_content:
                break
        
        # Fichier des destinataires
        while True:
            recipients_file = input(f"{Colors.CYAN}📧 Fichier destinataires:{Colors.RESET} ").strip()
            
            if not recipients_file:
                self.print_error("Chemin fichier destinataires requis")
                continue
            
            if not self.validate_file_path(recipients_file, "destinataires"):
                continue
            
            self.recipients = self.load_recipients(recipients_file)
            if self.recipients:
                break
        
        # Paramètres avancés
        self.print_section("⚙️ PARAMÈTRES AVANCÉS", Colors.PURPLE)
        
        # Délai
        delay_input = input(f"{Colors.CYAN}⏱️  Délai entre emails (ms) [{self.email_delay*1000:.0f}]:{Colors.RESET} ").strip()
        if delay_input:
            try:
                self.email_delay = float(delay_input) / 1000
            except ValueError:
                self.print_warning("Délai invalide, utilisation de la valeur par défaut")
        
        # Threads
        threads_input = input(f"{Colors.CYAN}🧵 Nombre de threads [{self.max_workers}]:{Colors.RESET} ").strip()
        if threads_input:
            try:
                self.max_workers = int(threads_input)
            except ValueError:
                self.print_warning("Nombre de threads invalide, utilisation de la valeur par défaut")
        
        # 5. Confirmation et lancement
        self.print_section("🚀 CONFIRMATION", Colors.RED)
        
        print(f"{Colors.BOLD}📊 RÉCAPITULATIF:{Colors.RESET}")
        print(f"  {Colors.BLUE}👥 Destinataires:{Colors.RESET} {Colors.BOLD}{len(self.recipients):,}{Colors.RESET}")
        print(f"  {Colors.BLUE}🖥️  Serveurs SMTP:{Colors.RESET} {Colors.BOLD}{len(self.working_smtps)}{Colors.RESET}")
        print(f"  {Colors.BLUE}📋 Sujet:{Colors.RESET} {Colors.BOLD}{self.subject}{Colors.RESET}")
        print(f"  {Colors.BLUE}👤 Expéditeur:{Colors.RESET} {Colors.BOLD}{self.sender_name}{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️  Délai:{Colors.RESET} {Colors.BOLD}{self.email_delay*1000:.0f}ms{Colors.RESET}")
        
        confirmation = input(f"\n{Colors.RED}{Colors.BOLD}🚀 Lancer l'envoi en masse? (o/N):{Colors.RESET} ").strip().lower()
        
        if confirmation in ['o', 'oui', 'y', 'yes']:
            self.print_info("🚀 Lancement de l'envoi en masse...")
            self.send_bulk_emails_fast()
        else:
            self.print_info("❌ Envoi annulé")

def main():
    """Fonction principale"""
    try:
        # Vérification Python 3.6+
        if sys.version_info < (3, 6):
            print(f"{Colors.RED}❌ Python 3.6+ requis{Colors.RESET}")
            sys.exit(1)
        
        # Création du mailer
        mailer = SMTPMailer()
        
        # Configuration interactive
        mailer.interactive_setup()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Interruption utilisateur{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Erreur fatale: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()