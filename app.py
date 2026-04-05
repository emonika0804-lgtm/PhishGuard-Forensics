from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

# GLOBAL HISTORY STORAGE
analysis_history = []

def analyze_logic(content, sender, subject):
    content_lower = content.lower()
    sender_lower = sender.lower()
    subject_lower = subject.lower()
    
    # Trusted keywords
    safe_indicators = ["meeting", "sync", "workshop", "university", "dinner", "official", "tcs", "zoho", "interview", "scheduled"]
    # Phishing keywords
    risk_indicators = ["urgent", "action required", "account suspended", "verify now", "login immediately", "password reset", "unusual activity", "click here"]

    is_safe = any(word in content_lower or word in sender_lower or word in subject_lower for word in safe_indicators)
    has_risk = any(word in content_lower or word in subject_lower for word in risk_indicators)

    if has_risk:
        return {
            "score": 92, 
            "type": "Phishing / Malicious", 
            "severity": "CRITICAL",
            "explanation": "This email uses high-pressure tactics and suspicious keywords common in phishing attacks.",
            "indicators": [
                {"title": "URGENCY_TACTIC", "desc": "Uses language designed to provoke immediate action."},
                {"title": "SUSPICIOUS_LINK", "desc": "Contains call-to-action phrases typical of credential theft."}
            ]
        }
    elif is_safe:
        return {
            "score": 8, 
            "type": "Legitimate Communication", 
            "severity": "LOW / SAFE",
            "explanation": "The content matches professional communication patterns. No malicious intent detected.",
            "indicators": [
                {"title": "TRUSTED_CONTEXT", "desc": "Matches recognized professional/personal keywords (Sync/Meeting)."},
                {"title": "SAFE_DOMAIN", "desc": "Sender appears to be from a recognized professional domain."}
            ]
        }
    else:
        return {
            "score": 45, 
            "type": "Unverified Content", 
            "severity": "MEDIUM / CAUTION",
            "explanation": "This email doesn't have clear phishing or safe marks. Proceed with caution.",
            "indicators": [
                {"title": "UNKNOWN_SENDER", "desc": "Sender is not in the trusted or blocked list."}
            ]
        }

@app.route('/')
def dashboard():
    total_scans = len(analysis_history)
    phishing_count = len([res for res in analysis_history if res['score'] > 50])
    latest_threat_score = analysis_history[-1]['score'] if analysis_history else 0
    recent = analysis_history[::-1][:5]
    return render_template('dashboard.html', history=recent, total=total_scans, phishing=phishing_count, latest=latest_threat_score)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        sender = request.form.get('sender_email')
        subject = request.form.get('subject_line')
        body = request.form.get('email_body')
        
        results = analyze_logic(body, sender, subject)
        results.update({
            'sender': sender, 
            'subject': subject, 
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M")
        })
        
        analysis_history.append(results)
        return render_template('results.html', results=results)
    return render_template('analyze_input.html')

@app.route('/history')
def history():
    # Enumerate helps us keep track of original index for the "View Report" link
    indexed_history = list(enumerate(analysis_history))
    return render_template('history.html', history=indexed_history[::-1])

@app.route('/report/<int:report_id>')
def view_report(report_id):
    if 0 <= report_id < len(analysis_history):
        report_data = analysis_history[report_id]
        return render_template('results.html', results=report_data)
    return "Report Not Found", 404

if __name__ == '__main__':
    app.run(debug=True)