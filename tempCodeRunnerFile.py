from flask import Flask, render_template, request, redirect, url_for, session  
import re  
import bcrypt  
from urllib.parse import urlparse  
import smtplib  
from email.mime.text import MIMEText  
from email.mime.multipart import MIMEMultipart  
import os  
from dotenv import load_dotenv  

# Load environment variables from .env file  
load_dotenv()  

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")  
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")  
SECRET_KEY = os.getenv("SECRET_KEY")  

app = Flask(__name__)  
app.secret_key = SECRET_KEY  

# Dummy database (Replace with a real database)  
USER_CREDENTIALS = {}  

def send_email(name, age, address, email):  
    """Send an email when a new user registers."""  
    try:  
        msg = MIMEMultipart()  
        msg["From"] = EMAIL_ADDRESS  
        msg["To"] = EMAIL_ADDRESS  # Admin email  
        msg["Subject"] = "New User Signup"  

        body = f"New user signed up:\n\nName: {name}\nAge: {age}\nAddress: {address}\nEmail: {email}"  
        msg.attach(MIMEText(body, "plain"))  

        server = smtplib.SMTP("smtp.gmail.com", 587)  
        server.starttls()  
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)  
        server.sendmail(EMAIL_ADDRESS, EMAIL_ADDRESS, msg.as_string())  
        server.quit()  
    except Exception as e:  
        print(f"Email sending failed: {e}")  

def analyze_url(url):  
    """Analyze URL for phishing risks."""  
    indicators = []  
    score = 0  

    if not url.startswith(('http://', 'https://')):  
        url = 'http://' + url  

    try:  
        parsed_url = urlparse(url)  
        domain = parsed_url.hostname if parsed_url.hostname else ''  

        if parsed_url.scheme != 'https':  
            indicators.append({'type': 'suspicious', 'text': 'Not using HTTPS'})  
            score += 15  
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']  
        tld = '.' + domain.split('.')[-1]  
        if tld in suspicious_tlds:  
            indicators.append({'type': 'suspicious', 'text': f'Suspicious TLD ({tld})'})  
            score += 10  

        if len(domain) > 30:  
            indicators.append({'type': 'suspicious', 'text': 'Long domain name'})  
            score += 10  

        subdomain_count = domain.count('.') - 1  
        if subdomain_count > 3:  
            indicators.append({'type': 'suspicious', 'text': 'Too many subdomains'})  
            score += 15  

        if re.search(r'[0-9-]', domain.split('.')[0]):  
            indicators.append({'type': 'neutral', 'text': 'Numbers/hyphens in domain'})  
            score += 5  

        popular_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google']  
        domain_without_tld = domain.rsplit('.', 1)[0]  

        for brand in popular_brands:  
            if brand in domain_without_tld and not domain_without_tld.endswith(brand):  
                indicators.append({'type': 'dangerous', 'text': f'Possible phishing ({brand})'})  
                score += 25  
                break  

        if len(parsed_url.path) > 100:  
            indicators.append({'type': 'suspicious', 'text': 'Long URL path'})  
            score += 10  

        suspicious_keywords = ['login', 'signin', 'verify', 'account']  
        if any(keyword in url.lower() for keyword in suspicious_keywords):  
            indicators.append({'type': 'neutral', 'text': 'Suspicious keywords in URL'})  
            score += 5  

        if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url):  
            indicators.append({'type': 'dangerous', 'text': 'IP address in URL'})  
            score += 30  

        if not any(i['type'] != 'safe' for i in indicators):  
            indicators.append({'type': 'safe', 'text': 'No major risks detected'})  

        score = min(score, 100)  

        risk_level = "Low Risk" if score < 20 else "Medium Risk" if score < 50 else "High Risk"  

        return {  
            'risk_score': score,  
            'risk_level': risk_level,  
            'indicators': indicators  
        }  
    except Exception:  
        return {'risk_score': 0, 'risk_level': 'Invalid URL'}  

@app.route('/register', methods=['GET', 'POST'])  
def register():  
    if request.method == 'POST':  
        name = request.form['name']  
        age = request.form['age']  
        address = request.form['address']  
        email = request.form['email']  
        password = request.form['password']  

        if email in USER_CREDENTIALS:  
            return "User already exists!"  

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  
        USER_CREDENTIALS[email] = {"name": name, "age": age, "address": address, "password": hashed_password}  

        send_email(name, age, address, email)  
        return redirect(url_for('login'))  

    return render_template('registration.html')  

@app.route('/login', methods=['GET', 'POST'])  
def login():  
    if request.method == 'POST':  
        email = request.form['email']  
        password = request.form['password']  

        if email in USER_CREDENTIALS and bcrypt.checkpw(password.encode('utf-8'), USER_CREDENTIALS[email]['password']):  
            session['logged_in'] = True  
            session['user_email'] = email  
            return redirect(url_for('index'))  
        return render_template('login.html', error_message="Invalid credentials!")  

    return render_template('login.html')  

@app.route('/logout')  
def logout():  
    session.pop('logged_in', None)  
    session.pop('user_email', None)  
    return redirect(url_for('login'))  

@app.route('/', methods=['GET', 'POST'])  
def index():  
    if 'logged_in' not in session:  
        return redirect(url_for('login'))  

    result = None  
    if request.method == 'POST':  
        url = request.form['url']  
        result = analyze_url(url)  

    return render_template('index.html', result=result)  

if __name__ == '__main__':  
    app.run(debug=True)  
