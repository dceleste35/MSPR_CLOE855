from flask import Flask, render_template_string, render_template, jsonify, request, redirect, url_for, session
from flask import render_template
from flask import json
from urllib.request import urlopen
from werkzeug.utils import secure_filename
from threat_detector import ThreatDetector
import sqlite3

threat_detector = ThreatDetector()

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'  # Clé secrète pour les sessions

# Fonction pour créer une clé "authentifie" dans la session utilisateur
def est_authentifie():
    return session.get('authentifie')

@app.route('/')
def hello_world():
    return render_template('hello.html')

@app.route('/lecture')
def lecture():
    if not est_authentifie():
        # Rediriger vers la page d'authentification si l'utilisateur n'est pas authentifié
        return redirect(url_for('authentification'))

  # Si l'utilisateur est authentifié
    return "<h2>Bravo, vous êtes authentifié</h2>"

@app.route('/authentification', methods=['GET', 'POST'])
def authentification():
    if request.method == 'POST':

        ip_address = request.remote_addr
        username = request.form['username']

        if not threat_detector.check_input(username, ip_address) or not threat_detector.check_input(request.form['password'], ip_address):
            return render_template('formulaire_authentification.html', error="Tentative suspecte détectée")

        if not threat_detector.check_login_attempt(username, ip_address):
            print("Trop de tentatives, réessayez plus tard")
            return render_template('formulaire_authentification.html', error="Trop de tentatives, réessayez plus tard")

        if username == 'admin' and request.form['password'] == 'password':
            session['authentifie'] = True
            log_connection_attempt(username, True)
            return redirect(url_for('lecture'))
        else:
            log_connection_attempt(request.form['username'], False)
            return render_template('formulaire_authentification.html', error="Nom d'utilisateur ou mot de passe incorrect")

    return render_template('formulaire_authentification.html', error=None)

@app.route('/fiche_client/<int:post_id>')
def Readfiche(post_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM clients WHERE id = ?', (post_id,))
    data = cursor.fetchall()
    conn.close()
    # Rendre le template HTML et transmettre les données
    return render_template('read_data.html', data=data)

@app.route('/consultation/')
def ReadBDD():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM clients;')
    data = cursor.fetchall()
    conn.close()
    return render_template('read_data.html', data=data)

@app.route('/enregistrer_client', methods=['GET'])
def formulaire_client():
    return render_template('formulaire.html')  # afficher le formulaire

@app.route('/enregistrer_client', methods=['POST'])
def enregistrer_client():
    nom = request.form['nom']
    prenom = request.form['prenom']

    # Connexion à la base de données
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Exécution de la requête SQL pour insérer un nouveau client
    cursor.execute('INSERT INTO clients (created, nom, prenom, adresse) VALUES (?, ?, ?, ?)', (1002938, nom, prenom, "ICI"))
    conn.commit()
    conn.close()
    return redirect('/consultation/')  # Rediriger vers la page d'accueil après l'enregistrement

@app.route('/admin/logs')
def view_logs():
    if not est_authentifie():
        return redirect(url_for('authentification'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, username, ip_address, success, user_agent
        FROM connection_logs
        ORDER BY timestamp DESC
    ''')
    logs = cursor.fetchall()
    conn.close()

    return render_template('view_logs.html', logs=logs)

@app.route('/admin/security')
def view_threats():
    if not est_authentifie():
        return redirect(url_for('authentification'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, threat_type, ip_address, details, severity, status
        FROM security_threats
        ORDER BY timestamp DESC
    ''')
    threats = cursor.fetchall()
    conn.close()

    return render_template('view_threats.html', threats=threats)

def log_connection_attempt(username, success):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Récupérer les informations de la requête
    ip_address = request.remote_addr
    user_agent = request.user_agent.string

    cursor.execute('''
        INSERT INTO connection_logs (username, ip_address, success, user_agent)
        VALUES (?, ?, ?, ?)
    ''', (username, ip_address, success, user_agent))

    conn.commit()
    conn.close()

if __name__ == "__main__":
  app.run(debug=True)
