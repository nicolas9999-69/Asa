#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import smtplib
import os
import time
import threading
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
    """Classe pour détecter automatiquement les serveurs SMTP et ports"""
    
    def __init__(self):
        # Configuration des serveurs SMTP par domaine
        self.smtp_configs = {
            # Gmail
            'gmail.com': [('smtp.gmail.com', 587), ('smtp.gmail.com', 465)],
            'googlemail.com': [('smtp.gmail.com', 587), ('smtp.gmail.com', 465)],
            
            # Outlook/Hotmail
            'outlook.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
            'hotmail.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
            'live.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
            'msn.com': [('smtp-mail.outlook.com', 587), ('smtp.live.com', 587)],
            
            # Yahoo
            'yahoo.com': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
            'yahoo.fr': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
            'yahoo.co.uk': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
            'ymail.com': [('smtp.mail.yahoo.com', 587), ('smtp.mail.yahoo.com', 465)],
            
            # AOL
            'aol.com': [('smtp.aol.com', 587), ('smtp.aol.com', 465)],
            
            # iCloud
            'icloud.com': [('smtp.mail.me.com', 587), ('smtp.mail.me.com', 465)],
            'me.com': [('smtp.mail.me.com', 587), ('smtp.mail.me.com', 465)],
            
            # Zoho
            'zoho.com': [('smtp.zoho.com', 587), ('smtp.zoho.com', 465)],
            'zohomail.com': [('smtp.zoho.com', 587), ('smtp.zoho.com', 465)],
            
            # ProtonMail
            'protonmail.com': [('127.0.0.1', 1025)],  # Nécessite bridge
            'proton.me': [('127.0.0.1', 1025)],
            
            # Autres fournisseurs populaires
            'mail.com': [('smtp.mail.com', 587), ('smtp.mail.com', 465)],
            'gmx.com': [('mail.gmx.com', 587), ('mail.gmx.com', 465)],
            'gmx.net': [('mail.gmx.net', 587), ('mail.gmx.net', 465)],
            'web.de': [('smtp.web.de', 587), ('smtp.web.de', 465)],
            
            # Fournisseurs français
            'orange.fr': [('smtp.orange.fr', 587), ('smtp.orange.fr', 465)],
            'wanadoo.fr': [('smtp.orange.fr', 587), ('smtp.orange.fr', 465)],
            'free.fr': [('smtp.free.fr', 587), ('smtp.free.fr', 465)],
            'sfr.fr': [('smtp.sfr.fr', 587), ('smtp.sfr.fr', 465)],
            'laposte.net': [('smtp.laposte.net', 587), ('smtp.laposte.net', 465)],
            
            # Domaines personnalisés - configurations génériques
            'default': [
                ('mail.{domain}', 587),
                ('smtp.{domain}', 587),
                ('mail.{domain}', 465),
                ('smtp.{domain}', 465),
                ('mail.{domain}', 25),
                ('smtp.{domain}', 25)
            ]
        }
    
    def extract_domain(self, email: str) -> str:
        """Extrait le domaine d'une adresse email"""
        return email.split('@')[1].lower()
    
    def get_smtp_candidates(self, email: str) -> List[Tuple[str, int]]:
        """Retourne les candidats SMTP pour un email donné"""
        domain = self.extract_domain(email)
        
        # Vérifier si le domaine est dans la configuration
        if domain in self.smtp_configs:
            return self.smtp_configs[domain]
        
        # Essayer les configurations génériques
        generic_configs = []
        for smtp_template, port in self.smtp_configs['default']:
            smtp_server = smtp_template.format(domain=domain)
            generic_configs.append((smtp_server, port))
        
        return generic_configs

class SMTPMailer:
    def __init__(self):
        self.smtp_detector = SMTPDetector()
        self.working_smtps = []
        self.test_email = ""
        self.sender_name = ""
        self.subject = ""
        self.html_content = ""
        self.recipients = []
        self.email_delay = 0.1
        self.stats = {
            'total_sent': 0,
            'total_failed': 0,
            'smtp_used': 0,
            'start_time': None,
            'end_time': None
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
        """Charge les identifiants email depuis un fichier mail:pass"""
        email_credentials = []
        invalid_lines = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            self.print_info(f"Analyse de {len(lines)} lignes dans le fichier identifiants...")
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Ignorer les lignes vides et commentaires
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                try:
                    # Diviser par ':' pour le format mail:pass
                    if ':' in line:
                        parts = line.split(':', 1)  # Diviser seulement au premier ':'
                    else:
                        self.print_warning(f"Ligne {line_num}: Format incorrect (attendu: email:password)")
                        invalid_lines += 1
                        continue
                    
                    if len(parts) != 2:
                        self.print_warning(f"Ligne {line_num}: Format incorrect (attendu: email:password)")
                        invalid_lines += 1
                        continue
                    
                    email, password = [part.strip() for part in parts]
                    
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
                    
                    email_credentials.append((email, password))
                    
                except Exception as e:
                    self.print_warning(f"Ligne {line_num}: Erreur de traitement - {e}")
                    invalid_lines += 1
                    
        except FileNotFoundError:
            self.print_error(f"Fichier identifiants non trouvé: {file_path}")
            return []
        except PermissionError:
            self.print_error(f"Permission refusée pour lire: {file_path}")
            return []
        except Exception as e:
            self.print_error(f"Erreur lors du chargement du fichier identifiants: {e}")
            return []
        
        # Résumé du chargement
        if invalid_lines > 0:
            self.print_warning(f"{invalid_lines} ligne(s) ignorée(s)")
        
        self.print_success(f"{len(email_credentials)} identifiant(s) email valide(s) chargé(s)")
        return email_credentials
    
    def test_smtp_connection(self, smtp_server: str, port: int, email: str, password: str) -> Tuple[bool, str]:
        """Test la validité d'une configuration SMTP avec diagnostic détaillé"""
        try:
            # Configuration du timeout
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(15)
            
            # Détermination du type de connexion
            if port == 587:
                server = smtplib.SMTP(smtp_server, port)
                server.starttls()
            elif port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port)
            elif port == 25:
                server = smtplib.SMTP(smtp_server, port)
            else:
                # Tentative de connexion automatique
                try:
                    server = smtplib.SMTP_SSL(smtp_server, port)
                except:
                    server = smtplib.SMTP(smtp_server, port)
                    try:
                        server.starttls()
                    except:
                        pass
            
            # Test d'authentification
            server.login(email, password)
            server.quit()
            
            # Restauration du timeout
            socket.setdefaulttimeout(original_timeout)
            
            return True, "Connexion réussie"
            
        except smtplib.SMTPAuthenticationError as e:
            return False, f"Échec authentification: {e.smtp_error.decode() if hasattr(e, 'smtp_error') else str(e)}"
        except smtplib.SMTPConnectError as e:
            return False, f"Échec connexion: {e.smtp_error.decode() if hasattr(e, 'smtp_error') else str(e)}"
        except smtplib.SMTPServerDisconnected:
            return False, "Serveur déconnecté"
        except smtplib.SMTPRecipientsRefused:
            return False, "Destinataire refusé"
        except smtplib.SMTPException as e:
            return False, f"Erreur SMTP: {str(e)}"
        except socket.timeout:
            return False, "Timeout de connexion"
        except socket.gaierror:
            return False, "Résolution DNS échouée"
        except Exception as e:
            return False, f"Erreur inattendue: {str(e)}"
        finally:
            socket.setdefaulttimeout(original_timeout)
    
    def send_test_email(self, smtp_server: str, port: int, email: str, password: str, test_recipient: str) -> Tuple[bool, str]:
        """Envoie un email de test avec diagnostic détaillé"""
        try:
            # Configuration du message de test
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.sender_name} <{email}>"
            msg['To'] = test_recipient
            msg['Subject'] = Header("🔍 Test SMTP - Vérification Fonctionnement", 'utf-8')
            
            # Contenu HTML de test élégant
            test_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; padding: 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }}
                    .header {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); padding: 30px; text-align: center; }}
                    .header h1 {{ color: white; margin: 0; font-size: 28px; text-shadow: 0 2px 4px rgba(0,0,0,0.3); }}
                    .content {{ padding: 30px; }}
                    .status {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                    .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                    .info-table th, .info-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                    .info-table th {{ background: #f8f9fa; font-weight: bold; }}
                    .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; font-size: 14px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🚀 Test SMTP Réussi</h1>
                    </div>
                    <div class="content">
                        <div class="status">
                            <strong>✅ Statut:</strong> Serveur SMTP fonctionnel et opérationnel
                        </div>
                        <table class="info-table">
                            <tr><th>🖥️ Serveur SMTP</th><td>{smtp_server}</td></tr>
                            <tr><th>🔌 Port</th><td>{port}</td></tr>
                            <tr><th>📧 Email</th><td>{email}</td></tr>
                            <tr><th>⏰ Timestamp</th><td>{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</td></tr>
                            <tr><th>👤 Expéditeur</th><td>{self.sender_name}</td></tr>
                        </table>
                        <p><strong>Ce message confirme que le serveur SMTP est correctement configuré et prêt pour l'envoi en masse.</strong></p>
                    </div>
                    <div class="footer">
                        Système de test SMTP automatisé | {datetime.now().year}
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(test_html, 'html', 'utf-8'))
            
            # Connexion et envoi
            if port == 587:
                server = smtplib.SMTP(smtp_server, port)
                server.starttls()
            elif port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port)
            else:
                server = smtplib.SMTP(smtp_server, port)
                try:
                    server.starttls()
                except:
                    pass
            
            server.login(email, password)
            server.send_message(msg)
            server.quit()
            
            return True, "Test email envoyé avec succès"
            
        except Exception as e:
            return False, f"Échec envoi test: {str(e)}"
    
    def find_working_smtp(self, email: str, password: str) -> Tuple[Optional[str], Optional[int], str]:
        """Trouve un serveur SMTP fonctionnel pour un email donné"""
        domain = self.smtp_detector.extract_domain(email)
        candidates = self.smtp_detector.get_smtp_candidates(email)
        
        print(f"    {Colors.DIM}🔍 Domaine détecté: {domain}{Colors.RESET}")
        print(f"    {Colors.DIM}🎯 {len(candidates)} candidat(s) SMTP à tester{Colors.RESET}")
        
        for i, (smtp_server, port) in enumerate(candidates):
            print(f"    {Colors.DIM}   [{i+1}/{len(candidates)}] Test: {smtp_server}:{port}{Colors.RESET}", end=' ')
            
            is_connected, message = self.test_smtp_connection(smtp_server, port, email, password)
            
            if is_connected:
                print(f"{Colors.GREEN}✅{Colors.RESET}")
                return smtp_server, port, message
            else:
                print(f"{Colors.RED}❌{Colors.RESET}")
                print(f"    {Colors.DIM}       Erreur: {message}{Colors.RESET}")
        
        return None, None, "Aucun serveur SMTP fonctionnel trouvé"
    
    def validate_email_credentials(self, email_credentials: List[Tuple[str, str]]) -> None:
        """Valide tous les identifiants email avec auto-détection SMTP"""
        self.print_section("AUTO-DÉTECTION ET VALIDATION SMTP", Colors.MAGENTA)
        
        if not email_credentials:
            self.print_error("Aucun identifiant email à tester")
            return
        
        progress = ProgressBar(len(email_credentials))
        
        for i, (email, password) in enumerate(email_credentials):
            print(f"\n{Colors.YELLOW}[{i+1:02d}/{len(email_credentials):02d}]{Colors.RESET} {Colors.BOLD}Email:{Colors.RESET} {Colors.CYAN}{email}{Colors.RESET}")
            
            # Recherche du serveur SMTP
            print(f"  {Colors.BLUE}🔍 Recherche serveur SMTP...{Colors.RESET}")
            smtp_server, port, conn_msg = self.find_working_smtp(email, password)
            
            if smtp_server and port:
                print(f"  {Colors.GREEN}✅ SMTP trouvé: {smtp_server}:{port}{Colors.RESET}")
                
                # Test d'envoi
                print(f"  {Colors.BLUE}📤 Test envoi email...{Colors.RESET}", end=' ')
                sys.stdout.flush()
                
                is_sent, send_msg = self.send_test_email(smtp_server, port, email, password, self.test_email)
                
                if is_sent:
                    print(f"{Colors.GREEN}✅ OK{Colors.RESET}")
                    self.working_smtps.append((smtp_server, port, email, password))
                    print(f"  {Colors.LIME}🎉 Configuration validée et ajoutée{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ KO{Colors.RESET}")
                    print(f"  {Colors.DIM}   Raison: {send_msg}{Colors.RESET}")
            else:
                print(f"  {Colors.RED}❌ Aucun serveur SMTP fonctionnel trouvé{Colors.RESET}")
                print(f"  {Colors.DIM}   Raison: {conn_msg}{Colors.RESET}")
            
            progress.update(i + 1)
        
        progress.finish()
        
        # Résumé final
        working_count = len(self.working_smtps)
        total_count = len(email_credentials)
        success_rate = (working_count / total_count * 100) if total_count > 0 else 0
        
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 RÉSUMÉ DE VALIDATION:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Fonctionnels:{Colors.RESET} {Colors.BOLD}{working_count}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Défaillants:{Colors.RESET} {Colors.BOLD}{total_count - working_count}{Colors.RESET}")
        print(f"  {Colors.YELLOW}📈 Taux de réussite:{Colors.RESET} {Colors.BOLD}{success_rate:.1f}%{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}")
    
    def load_recipients(self, file_path: str) -> List[str]:
        """Charge la liste des destinataires (sans supprimer les doublons)"""
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
                    recipients.append(email)  # Garder tous les emails, même les doublons
                else:
                    self.print_warning(f"Ligne {line_num}: Email invalide '{email}'")
                    invalid_emails += 1
                    
        except FileNotFoundError:
            self.print_error(f"Fichier destinataires non trouvé: {file_path}")
            return []
        except PermissionError:
            self.print_error(f"Permission refusée pour lire: {file_path}")
            return []
        except Exception as e:
            self.print_error(f"Erreur chargement destinataires: {e}")
            return []
        
        # Résumé du chargement
        if invalid_emails > 0:
            self.print_warning(f"{invalid_emails} email(s) invalide(s) ignoré(s)")
        
        unique_count = len(set(recipients))
        duplicate_count = len(recipients) - unique_count
        
        self.print_success(f"{len(recipients)} destinataire(s) chargé(s)")
        if duplicate_count > 0:
            self.print_info(f"Doublons conservés: {duplicate_count} (total unique: {unique_count})")
        
        return recipients
    
    def load_html_template(self, file_path: str) -> str:
        """Charge et valide le template HTML"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Validation basique du HTML
            if not content.strip():
                self.print_error("Fichier HTML vide")
                return ""
            
            # Vérifications basiques
            has_html_tags = any(tag in content.lower() for tag in ['<html>', '<body>', '<div>', '<p>', '<h1>', '<h2>', '<h3>'])
            
            if not has_html_tags:
                self.print_warning("Le fichier ne semble pas contenir de balises HTML valides")
            
            size_kb = len(content.encode('utf-8')) / 1024
            self.print_success(f"Template HTML chargé ({size_kb:.1f} KB, {len(content)} caractères)")
            
            return content
            
        except FileNotFoundError:
            self.print_error(f"Fichier HTML non trouvé: {file_path}")
            return ""
        except PermissionError:
            self.print_error(f"Permission refusée pour lire: {file_path}")
            return ""
        except UnicodeDecodeError:
            self.print_error("Erreur d'encodage du fichier HTML")
            return ""
        except Exception as e:
            self.print_error(f"Erreur chargement HTML: {e}")
            return ""
    
    def send_bulk_emails(self) -> None:
        """Envoie les emails en lot avec rotation des SMTP et statistiques détaillées"""
        if not self.working_smtps:
            self.print_error("Aucun serveur SMTP fonctionnel disponible")
            return
        
        if not self.recipients:
            self.print_error("Aucun destinataire chargé")
            return
        
        if not self.html_content:
            self.print_error("Aucun contenu HTML chargé")
            return
        
        self.print_section("ENVOI EN MASSE", Colors.GREEN)
        
        # Affichage des paramètres
        print(f"{Colors.CYAN}📊 PARAMÈTRES D'ENVOI:{Colors.RESET}")
        print(f"  {Colors.BLUE}👥 Destinataires:{Colors.RESET} {Colors.BOLD}{len(self.recipients):,}{Colors.RESET}")
        print(f"  {Colors.BLUE}🖥️  Serveurs SMTP:{Colors.RESET} {Colors.BOLD}{len(self.working_smtps)}{Colors.RESET}")
        print(f"  {Colors.BLUE}📧 Emails par serveur:{Colors.RESET} {Colors.BOLD}200 max{Colors.RESET}")
        print(f"  {Colors.BLUE}⏱️  Délai entre emails:{Colors.RESET} {Colors.BOLD}{self.email_delay}s{Colors.RESET}")
        print(f"  {Colors.BLUE}👤 Expéditeur:{Colors.RESET} {Colors.BOLD}{self.sender_name}{Colors.RESET}")
        print(f"  {Colors.BLUE}📝 Sujet:{Colors.RESET} {Colors.BOLD}{self.subject}{Colors.RESET}")

        # Estimation du temps
        estimated_time = len(self.recipients) * self.email_delay
        estimated_minutes = estimated_time / 60
        print(f"  {Colors.BLUE}⏰ Temps estimé:{Colors.RESET} {Colors.BOLD}{estimated_minutes:.1f} minutes{Colors.RESET}")
        
        # Confirmation avant envoi
        print(f"\n{Colors.YELLOW}⚠️  Prêt à envoyer {len(self.recipients)} emails. Continuer ? (o/N):{Colors.RESET}", end=' ')
        confirm = input().strip().lower()
        
        if confirm not in ['o', 'oui', 'y', 'yes']:
            self.print_info("Envoi annulé par l'utilisateur")
            return
        
        # Initialisation des statistiques
        self.stats['start_time'] = datetime.now()
        self.stats['total_sent'] = 0
        self.stats['total_failed'] = 0
        self.stats['smtp_used'] = len(self.working_smtps)
        
        # Variables pour la rotation et limitation
        smtp_index = 0
        emails_per_smtp = {}
        max_emails_per_smtp = 200
        
        # Initialiser les compteurs par SMTP
        for i, (smtp_server, port, email, password) in enumerate(self.working_smtps):
            emails_per_smtp[i] = 0
        
        # Barre de progression
        progress = ProgressBar(len(self.recipients))
        
        print(f"\n{Colors.GREEN}🚀 DÉBUT DE L'ENVOI EN MASSE{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        
        # Envoi des emails
        for i, recipient in enumerate(self.recipients):
            try:
                # Vérifier si le SMTP actuel a atteint la limite
                if emails_per_smtp[smtp_index] >= max_emails_per_smtp:
                    # Chercher le prochain SMTP disponible
                    original_smtp_index = smtp_index
                    while emails_per_smtp[smtp_index] >= max_emails_per_smtp:
                        smtp_index = (smtp_index + 1) % len(self.working_smtps)
                        # Si on a fait le tour complet, tous les SMTP sont saturés
                        if smtp_index == original_smtp_index:
                            self.print_warning("Tous les serveurs SMTP ont atteint leur limite")
                            break
                
                # Récupérer la configuration SMTP actuelle
                smtp_server, port, sender_email, password = self.working_smtps[smtp_index]
                
                # Envoyer l'email
                success, error_msg = self.send_single_email(
                    smtp_server, port, sender_email, password, recipient
                )
                
                if success:
                    self.stats['total_sent'] += 1
                    emails_per_smtp[smtp_index] += 1
                    
                    # Affichage du succès (occasionnel pour ne pas surcharger)
                    if i % 10 == 0 or i < 5:
                        print(f"  {Colors.GREEN}✅ {recipient} via {smtp_server}{Colors.RESET}")
                else:
                    self.stats['total_failed'] += 1
                    print(f"  {Colors.RED}❌ {recipient}: {error_msg}{Colors.RESET}")
                
                # Rotation vers le prochain SMTP
                smtp_index = (smtp_index + 1) % len(self.working_smtps)
                
                # Mise à jour de la barre de progression
                progress.update(i + 1)
                
                # Délai entre les emails
                if self.email_delay > 0:
                    time.sleep(self.email_delay)
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}⚠️  Envoi interrompu par l'utilisateur{Colors.RESET}")
                break
            except Exception as e:
                self.stats['total_failed'] += 1
                print(f"  {Colors.RED}❌ Erreur inattendue pour {recipient}: {e}{Colors.RESET}")
                progress.update(i + 1)
        
        progress.finish()
        
        # Statistiques finales
        self.stats['end_time'] = datetime.now()
        self.display_final_stats()
    
    def send_single_email(self, smtp_server: str, port: int, sender_email: str, password: str, recipient: str) -> Tuple[bool, str]:
        """Envoie un email individuel avec gestion d'erreurs détaillée"""
        try:
            # Création du message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.sender_name} <{sender_email}>"
            msg['To'] = recipient
            msg['Subject'] = Header(self.subject, 'utf-8')
            
            # Ajout du contenu HTML
            msg.attach(MIMEText(self.html_content, 'html', 'utf-8'))
            
            # Connexion au serveur SMTP
            if port == 587:
                server = smtplib.SMTP(smtp_server, port)
                server.starttls()
            elif port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port)
            else:
                server = smtplib.SMTP(smtp_server, port)
                try:
                    server.starttls()
                except:
                    pass
            
            # Authentification et envoi
            server.login(sender_email, password)
            server.send_message(msg)
            server.quit()
            
            return True, "Email envoyé avec succès"
            
        except smtplib.SMTPAuthenticationError:
            return False, "Échec authentification SMTP"
        except smtplib.SMTPRecipientsRefused:
            return False, "Destinataire refusé"
        except smtplib.SMTPServerDisconnected:
            return False, "Serveur SMTP déconnecté"
        except smtplib.SMTPException as e:
            return False, f"Erreur SMTP: {str(e)}"
        except Exception as e:
            return False, f"Erreur: {str(e)}"
    
    def display_final_stats(self) -> None:
        """Affiche les statistiques finales de l'envoi"""
        self.print_section("STATISTIQUES FINALES", Colors.PURPLE)
        
        # Calcul des durées
        duration = self.stats['end_time'] - self.stats['start_time']
        duration_minutes = duration.total_seconds() / 60
        
        # Calcul des taux
        total_emails = self.stats['total_sent'] + self.stats['total_failed']
        success_rate = (self.stats['total_sent'] / total_emails * 100) if total_emails > 0 else 0
        emails_per_minute = (self.stats['total_sent'] / duration_minutes) if duration_minutes > 0 else 0
        
        # Affichage des statistiques
        print(f"{Colors.CYAN}📊 RÉSUMÉ DE L'ENVOI:{Colors.RESET}")
        print(f"  {Colors.GREEN}✅ Emails envoyés:{Colors.RESET} {Colors.BOLD}{self.stats['total_sent']:,}{Colors.RESET}")
        print(f"  {Colors.RED}❌ Emails échoués:{Colors.RESET} {Colors.BOLD}{self.stats['total_failed']:,}{Colors.RESET}")
        print(f"  {Colors.BLUE}📈 Taux de réussite:{Colors.RESET} {Colors.BOLD}{success_rate:.1f}%{Colors.RESET}")
        print(f"  {Colors.YELLOW}⏱️  Durée totale:{Colors.RESET} {Colors.BOLD}{duration_minutes:.1f} minutes{Colors.RESET}")
        print(f"  {Colors.PURPLE}🚀 Vitesse d'envoi:{Colors.RESET} {Colors.BOLD}{emails_per_minute:.1f} emails/min{Colors.RESET}")
        print(f"  {Colors.MAGENTA}🖥️  Serveurs SMTP utilisés:{Colors.RESET} {Colors.BOLD}{self.stats['smtp_used']}{Colors.RESET}")
        
        # Affichage par état
        if self.stats['total_sent'] > 0:
            print(f"\n{Colors.GREEN}🎉 Envoi terminé avec succès !{Colors.RESET}")
        elif self.stats['total_failed'] > 0:
            print(f"\n{Colors.RED}⚠️  Envoi terminé avec des erreurs{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}ℹ️  Aucun email envoyé{Colors.RESET}")
    
    def interactive_setup(self) -> bool:
        """Configuration interactive du mailer"""
        self.print_header("🚀 CONFIGURATION INTERACTIVE SMTP MAILER", Colors.PURPLE)
        
        try:
            # 1. Fichier des identifiants email
            print(f"{Colors.CYAN}📁 ÉTAPE 1: Fichier des identifiants email{Colors.RESET}")
            print(f"  {Colors.DIM}Format attendu: email:password (un par ligne){Colors.RESET}")
            
            while True:
                email_file = input(f"{Colors.YELLOW}Chemin du fichier identifiants:{Colors.RESET} ").strip()
                if self.validate_file_path(email_file, "identifiants"):
                    break
                print(f"  {Colors.RED}Veuillez entrer un chemin valide{Colors.RESET}")
            
            # 2. Email de test
            print(f"\n{Colors.CYAN}📧 ÉTAPE 2: Email de test{Colors.RESET}")
            print(f"  {Colors.DIM}Un email de test sera envoyé à cette adresse pour valider les SMTP{Colors.RESET}")
            
            while True:
                test_email = input(f"{Colors.YELLOW}Email de test:{Colors.RESET} ").strip()
                if self.validate_email(test_email):
                    self.test_email = test_email
                    break
                print(f"  {Colors.RED}Format d'email invalide{Colors.RESET}")
            
            # 3. Nom de l'expéditeur
            print(f"\n{Colors.CYAN}👤 ÉTAPE 3: Nom de l'expéditeur{Colors.RESET}")
            sender_name = input(f"{Colors.YELLOW}Nom de l'expéditeur:{Colors.RESET} ").strip()
            self.sender_name = sender_name if sender_name else "Expéditeur"
            
            # 4. Sujet de l'email
            print(f"\n{Colors.CYAN}📝 ÉTAPE 4: Sujet de l'email{Colors.RESET}")
            subject = input(f"{Colors.YELLOW}Sujet:{Colors.RESET} ").strip()
            self.subject = subject if subject else "Message important"
            
            # 5. Fichier HTML
            print(f"\n{Colors.CYAN}🎨 ÉTAPE 5: Template HTML{Colors.RESET}")
            print(f"  {Colors.DIM}Fichier contenant le corps de l'email en HTML{Colors.RESET}")
            
            while True:
                html_file = input(f"{Colors.YELLOW}Chemin du fichier HTML:{Colors.RESET} ").strip()
                if self.validate_file_path(html_file, "HTML"):
                    break
                print(f"  {Colors.RED}Veuillez entrer un chemin valide{Colors.RESET}")
            
            # 6. Fichier des destinataires
            print(f"\n{Colors.CYAN}👥 ÉTAPE 6: Fichier des destinataires{Colors.RESET}")
            print(f"  {Colors.DIM}Un email par ligne{Colors.RESET}")
            
            while True:
                recipients_file = input(f"{Colors.YELLOW}Chemin du fichier destinataires:{Colors.RESET} ").strip()
                if self.validate_file_path(recipients_file, "destinataires"):
                    break
                print(f"  {Colors.RED}Veuillez entrer un chemin valide{Colors.RESET}")
            
            # 7. Délai entre emails
            print(f"\n{Colors.CYAN}⏱️  ÉTAPE 7: Délai entre emails{Colors.RESET}")
            print(f"  {Colors.DIM}Délai en secondes pour éviter le spam (recommandé: 0.1-1.0){Colors.RESET}")
            
            while True:
                try:
                    delay = input(f"{Colors.YELLOW}Délai (secondes) [0.1]:{Colors.RESET} ").strip()
                    if not delay:
                        delay = "0.1"
                    self.email_delay = float(delay)
                    if self.email_delay < 0:
                        print(f"  {Colors.RED}Le délai ne peut pas être négatif{Colors.RESET}")
                        continue
                    break
                except ValueError:
                    print(f"  {Colors.RED}Veuillez entrer un nombre valide{Colors.RESET}")
            
            # Résumé de la configuration
            print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
            print(f"{Colors.BOLD}📋 RÉSUMÉ DE LA CONFIGURATION:{Colors.RESET}")
            print(f"  {Colors.BLUE}📁 Fichier identifiants:{Colors.RESET} {email_file}")
            print(f"  {Colors.BLUE}📧 Email de test:{Colors.RESET} {self.test_email}")
            print(f"  {Colors.BLUE}👤 Expéditeur:{Colors.RESET} {self.sender_name}")
            print(f"  {Colors.BLUE}📝 Sujet:{Colors.RESET} {self.subject}")
            print(f"  {Colors.BLUE}🎨 Fichier HTML:{Colors.RESET} {html_file}")
            print(f"  {Colors.BLUE}👥 Fichier destinataires:{Colors.RESET} {recipients_file}")
            print(f"  {Colors.BLUE}⏱️  Délai:{Colors.RESET} {self.email_delay}s")
            print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}")
            
            # Chargement des données
            print(f"\n{Colors.MAGENTA}🔄 CHARGEMENT DES DONNÉES...{Colors.RESET}")
            
            # Chargement des identifiants
            email_credentials = self.load_email_credentials(email_file)
            if not email_credentials:
                self.print_error("Impossible de charger les identifiants email")
                return False
            
            # Chargement du contenu HTML
            self.html_content = self.load_html_template(html_file)
            if not self.html_content:
                self.print_error("Impossible de charger le template HTML")
                return False
            
            # Chargement des destinataires
            self.recipients = self.load_recipients(recipients_file)
            if not self.recipients:
                self.print_error("Impossible de charger les destinataires")
                return False
            
            # Validation des SMTP
            self.validate_email_credentials(email_credentials)
            
            if not self.working_smtps:
                self.print_error("Aucun serveur SMTP fonctionnel trouvé")
                return False
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⚠️  Configuration interrompue par l'utilisateur{Colors.RESET}")
            return False
        except Exception as e:
            self.print_error(f"Erreur lors de la configuration: {e}")
            return False
    
    def run(self) -> None:
        """Lance l'application principale"""
        try:
            # Configuration interactive
            if not self.interactive_setup():
                return
            
            # Lancement de l'envoi en masse
            self.send_bulk_emails()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⚠️  Application interrompue par l'utilisateur{Colors.RESET}")
        except Exception as e:
            self.print_error(f"Erreur fatale: {e}")
        finally:
            print(f"\n{Colors.CYAN}👋 Merci d'avoir utilisé SMTP Mailer !{Colors.RESET}")

def main():
    """Point d'entrée principal"""
    try:
        # Affichage du banner
        print(f"{Colors.PURPLE}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.PURPLE}║{Colors.BOLD}{Colors.WHITE}{'SMTP MAILER - AUTO-DETECTION & BULK SENDER'.center(78)}{Colors.RESET}{Colors.PURPLE}║{Colors.RESET}")
        print(f"{Colors.PURPLE}║{Colors.CYAN}{'Détection automatique des serveurs SMTP et envoi en masse'.center(78)}{Colors.RESET}{Colors.PURPLE}║{Colors.RESET}")
        print(f"{Colors.PURPLE}║{Colors.DIM}{'Version 2.0 - Python 3.x'.center(78)}{Colors.RESET}{Colors.PURPLE}║{Colors.RESET}")
        print(f"{Colors.PURPLE}{'═' * 80}{Colors.RESET}")
        
        # Création et lancement du mailer
        mailer = SMTPMailer()
        mailer.run()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Programme interrompu{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Erreur critique: {e}{Colors.RESET}")
    finally:
        print(f"\n{Colors.DIM}Appuyez sur Entrée pour quitter...{Colors.RESET}")
        input()

if __name__ == "__main__":
    main()