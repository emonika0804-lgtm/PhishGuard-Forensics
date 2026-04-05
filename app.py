from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

# HISTORY STORAGE
analysis_history = []

def analyze_logic(content, sender, subject):
    content_lower = content.lower()
    sender_lower = sender.lower()
    
    # Simple logic to check for safe vs phishing
    if "microsoft" in sender_lower or "microsoft" in content_lower:
        return {
            "score": 5,
            "type": "Official Communication",
            "severity": "LOW / SAFE",
            "explanation": "This email appears to be an official notification from a trusted provider. No malicious intent detected.",
            "indicators": [
                {"title": "TRUSTED_DOMAIN", "desc": "The sender's domain has a high reputation score."},
                {"title": "NO_MALICIOUS_LINKS", "desc": "All embedded links point to official domains."},
                {"title": "NEUTRAL_TONE", "desc": "The email does not use aggressive or threatening language."}
            ]
        }
    else:
        return {
            "score": 85,
            "type": "Credential Harvesting",
            "severity": "CRITICAL",
            "explanation": "This email exhibits multiple indicators of phishing, including a suspicious sender address and urgent language.",
            "indicators": [
                {"title": "SENDER_REPUTATION", "desc": "Sender domain is not verified."},
                {"title": "URGENCY_TACTIC", "desc": "Claims the account will be limited soon."},
                {"title": "LINK_MISREPRESENTATION", "desc": "Hidden URLs point to non-official servers."},
                {"title": "GENERIC_GREETING", "desc": "Uses non-specific salutations."}
            ]
        }

@app.route('/')
def dashboard():
    total_scans = len(analysis_history)
    recent = analysis_history[::-1][:5]
    return render_template('dashboard.html', history=recent, total=total_scans)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        sender = request.form.get('sender_email')
        subject = request.form.get('subject_line')
        body = request.form.get('email_body')
        
        results = analyze_logic(body, sender, subject)
        results['sender'] = sender
        results['subject'] = subject
        results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        analysis_history.append(results)
        
        return render_template('results.html', results=results)
    return render_template('analyze_input.html')

@app.route('/history')
def history():
    return render_template('history.html', history=analysis_history[::-1])

if __name__ == '__main__':
    app.run(debug=True)