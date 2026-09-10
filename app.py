"""
================================================================================
 EasyAlgo Backend — Reference Implementation (Python + Flask)
================================================================================

This is a REFERENCE / STARTER backend for the EasyAlgo trading app. It shows
the correct, working pattern for every piece you asked about:

    1. MongoDB          -> user accounts, OTPs, payments storage
    2. SMS OTP           -> Twilio  (mobile number verification)
    3. Gmail OTP          -> Gmail SMTP (email verification)
    4. Delta Exchange    -> signed REST API client (balance, positions, trade history)
    5. Payments (UPI / Google Pay / cards) -> Razorpay (Google Pay is not a
       standalone payment gateway you can call directly — it's one of the
       payment methods that a gateway like Razorpay/Cashfree offers to the
       payer automatically once you use them)

HOW TO RUN THIS:
    1. Install Python 3.10+ and MongoDB (or use a free MongoDB Atlas cluster)
    2. pip install -r requirements.txt
    3. Copy .env.example to .env and fill in your real keys
    4. python app.py
    5. Server runs at http://localhost:5000

PUTTING THIS ON GITHUB:
    - Create a new repo, push this folder to it.
    - NEVER commit your real .env file — it's already in .gitignore below.
    - On your hosting platform (Render / Railway / AWS), set the same
      environment variables from .env.example in their dashboard.
    - That hosting platform gives you the fixed IP address you then
      whitelist inside your Delta Exchange API settings.

SECURITY NOTE (read this before going live):
    - This file stores broker secrets as plain text for clarity. In a real
      deployment, ENCRYPT them before saving (e.g. with the `cryptography`
      package) and never log them.
    - Add rate-limiting to the OTP endpoints so they can't be spammed.
    - Use HTTPS everywhere — never send OTPs or secrets over plain HTTP.
================================================================================
"""

import os
import time
import hmac
import hashlib
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

import requests
import bcrypt
import razorpay
from flask import Flask, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()  # reads variables from a local .env file

app = Flask(__name__)


# ==============================================================================
# 1. CONFIG — every secret/key comes from environment variables, never hardcoded
# ==============================================================================
class Config:
    # ---- MongoDB ----
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "easyalgo")

    # ---- SMS OTP (Twilio — sign up at https://www.twilio.com) ----
    TWILIO_SID = os.getenv("TWILIO_SID")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
    TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER")

    # ---- Gmail OTP (use a Gmail "App Password", not your real password —
    #      generate one at https://myaccount.google.com/apppasswords ) ----
    GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
    GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

    # ---- Delta Exchange (https://docs.delta.exchange) ----
    DELTA_BASE_URL = os.getenv("DELTA_BASE_URL", "https://api.delta.exchange")

    # ---- Razorpay — handles UPI / Google Pay / PhonePe / cards / netbanking
    #      all through one integration (sign up at https://razorpay.com) ----
    RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
    RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
    RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")

    # Backend-registered admin mobile number (only this number can create
    # the admin account, matching what the EasyAlgo frontend expects)
    ADMIN_MOBILE = os.getenv("ADMIN_MOBILE", "9016334157")


cfg = Config()


# ==============================================================================
# 2. DATABASE — MongoDB collections
# ==============================================================================
mongo_client = MongoClient(cfg.MONGO_URI)
db = mongo_client[cfg.MONGO_DB_NAME]

users_col = db["users"]          # one document per trader account
otps_col = db["otps"]            # short-lived OTP records (mobile + email)
payments_col = db["payments"]    # every payment order Razorpay creates
admin_col = db["admin"]          # single admin account
strategies_col = db["strategies"]  # each user's custom strategies


# ==============================================================================
# 3. OTP — SMS (Twilio) + Email (Gmail SMTP)
# ==============================================================================
def generate_otp() -> str:
    return str(random.randint(1000, 9999))


def send_sms_otp(mobile_number: str, otp: str):
    """
    Sends an OTP by SMS using Twilio.
    Docs: https://www.twilio.com/docs/sms/quickstart/python
    """
    url = f"https://api.twilio.com/2010-04-01/Accounts/{cfg.TWILIO_SID}/Messages.json"
    payload = {
        "To": f"+91{mobile_number}",
        "From": cfg.TWILIO_FROM_NUMBER,
        "Body": f"Your EasyAlgo verification code is {otp}. Valid for 5 minutes.",
    }
    resp = requests.post(url, data=payload, auth=(cfg.TWILIO_SID, cfg.TWILIO_AUTH_TOKEN))
    resp.raise_for_status()
    return resp.json()


def send_email_otp(to_email: str, otp: str):
    """
    Sends an OTP by email using Gmail's SMTP server.
    You MUST use a Gmail "App Password" here, not your normal Gmail login
    password — Google blocks plain-password SMTP logins for security.
    """
    msg = MIMEText(f"Your EasyAlgo verification code is {otp}. Valid for 5 minutes.")
    msg["Subject"] = "EasyAlgo — Verification code"
    msg["From"] = cfg.GMAIL_ADDRESS
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(cfg.GMAIL_ADDRESS, cfg.GMAIL_APP_PASSWORD)
        server.send_message(msg)


def store_otp(key: str, otp: str, ttl_minutes: int = 5):
    otps_col.update_one(
        {"key": key},
        {"$set": {"otp": otp, "expires_at": datetime.utcnow() + timedelta(minutes=ttl_minutes)}},
        upsert=True,
    )


def verify_otp(key: str, otp_input: str) -> bool:
    record = otps_col.find_one({"key": key})
    if not record:
        return False
    if record["expires_at"] < datetime.utcnow():
        otps_col.delete_one({"key": key})
        return False
    if record["otp"] != otp_input:
        return False
    otps_col.delete_one({"key": key})  # OTP is single-use
    return True


# ==============================================================================
# 4. USER AUTH — signup (mobile + Gmail OTP), login (User ID + password)
# ==============================================================================
def make_user_id(name: str) -> str:
    """e.g. 'Rajesh Nayak' + 1st account created -> 'RN0001' """
    initials = "".join(word[0] for word in name.strip().split()).upper()[:3]
    serial = users_col.count_documents({}) + 1
    return f"{initials}{str(serial).zfill(4)}"


@app.route("/api/signup/send-otp", methods=["POST"])
def signup_send_otp():
    data = request.get_json(force=True)
    name, mobile, gmail = data.get("name"), data.get("mobile"), data.get("gmail")

    if not (name and mobile and gmail):
        return jsonify({"error": "name, mobile and gmail are required"}), 400
    if users_col.find_one({"mobile": mobile}):
        return jsonify({"error": "This mobile number is already registered"}), 400

    otp_mobile = generate_otp()
    otp_gmail = generate_otp()
    store_otp(f"signup_mobile_{mobile}", otp_mobile)
    store_otp(f"signup_gmail_{gmail}", otp_gmail)

    send_sms_otp(mobile, otp_mobile)
    send_email_otp(gmail, otp_gmail)

    return jsonify({"message": "OTP sent to mobile and Gmail"}), 200


@app.route("/api/signup/verify", methods=["POST"])
def signup_verify():
    data = request.get_json(force=True)
    name, mobile, gmail = data["name"], data["mobile"], data["gmail"]
    password = data["password"]
    otp_mobile_input, otp_gmail_input = data["otp_mobile"], data["otp_gmail"]

    if not verify_otp(f"signup_mobile_{mobile}", otp_mobile_input):
        return jsonify({"error": "Invalid or expired mobile OTP"}), 400
    if not verify_otp(f"signup_gmail_{gmail}", otp_gmail_input):
        return jsonify({"error": "Invalid or expired Gmail OTP"}), 400

    user_id = make_user_id(name)
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    users_col.insert_one({
        "user_id": user_id,
        "name": name,
        "mobile": mobile,
        "gmail": gmail,
        "password_hash": password_hash,
        "photo": None,
        "created_at": datetime.utcnow(),
        "pro_until": None,
        "broker_creds": {},   # filled in once the user connects a broker
    })

    return jsonify({"message": "Account created", "user_id": user_id}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    user_id, password = data["user_id"], data["password"]

    user = users_col.find_one({"user_id": user_id})
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"]):
        return jsonify({"error": "Incorrect User ID or password"}), 401

    # NOTE: in production, issue a real session/JWT token here instead of
    # just returning the user_id.
    return jsonify({"message": "Login successful", "user_id": user_id}), 200


# ==============================================================================
# 5. ADMIN AUTH — only the backend-registered mobile number can create/reset it
# ==============================================================================
@app.route("/api/admin/create/send-otp", methods=["POST"])
def admin_create_send_otp():
    data = request.get_json(force=True)
    mobile = data.get("mobile")

    if admin_col.find_one({}):
        return jsonify({"error": "An admin account already exists"}), 400
    if mobile != cfg.ADMIN_MOBILE:
        return jsonify({"error": "This number is not authorized for admin access"}), 403

    otp = generate_otp()
    store_otp(f"admin_create_{mobile}", otp)
    send_sms_otp(mobile, otp)
    return jsonify({"message": "OTP sent to the registered admin number"}), 200


@app.route("/api/admin/create/verify", methods=["POST"])
def admin_create_verify():
    data = request.get_json(force=True)
    username, mobile, password, otp = data["username"], data["mobile"], data["password"], data["otp"]

    if not verify_otp(f"admin_create_{mobile}", otp):
        return jsonify({"error": "Invalid or expired OTP"}), 400

    admin_col.insert_one({
        "username": username,
        "mobile": mobile,
        "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
    })
    return jsonify({"message": "Admin account created"}), 201


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(force=True)
    admin = admin_col.find_one({"username": data["username"]})
    if not admin or not bcrypt.checkpw(data["password"].encode(), admin["password_hash"]):
        return jsonify({"error": "Incorrect username or password"}), 401
    return jsonify({"message": "Admin login successful"}), 200


# ==============================================================================
# 6. DELTA EXCHANGE — signed REST client (balance, positions, trade history)
# ==============================================================================
class DeltaExchangeClient:
    """
    Thin wrapper around Delta Exchange's private REST API.
    Docs: https://docs.delta.exchange

    Every private request must be signed:
        signature_payload = method + timestamp + request_path + query_string + body
        signature = HMAC_SHA256(signature_payload, api_secret)
    sent back as headers: api-key, timestamp, signature
    """

    def __init__(self, api_key: str, api_secret: str, base_url: str = None):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url or cfg.DELTA_BASE_URL

    def _headers(self, method: str, path: str, query_string: str = "", body: str = ""):
        timestamp = str(int(time.time()))
        payload = method + timestamp + path + query_string + body
        signature = hmac.new(self.api_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return {
            "api-key": self.api_key,
            "timestamp": timestamp,
            "signature": signature,
            "Content-Type": "application/json",
        }

    def get_balance(self):
        path = "/v2/wallet/balances"
        resp = requests.get(self.base_url + path, headers=self._headers("GET", path))
        resp.raise_for_status()
        return resp.json()

    def get_positions(self):
        path = "/v2/positions"
        resp = requests.get(self.base_url + path, headers=self._headers("GET", path))
        resp.raise_for_status()
        return resp.json()

    def get_order_history(self, start_time: int = None, end_time: int = None):
        """start_time / end_time are Unix timestamps (seconds) — matches the
        'From / To date' filter on the EasyAlgo trade-history screen."""
        path = "/v2/orders/history"
        query = ""
        if start_time and end_time:
            query = f"?start_time={start_time}&end_time={end_time}"
        resp = requests.get(self.base_url + path + query, headers=self._headers("GET", path, query))
        resp.raise_for_status()
        return resp.json()


@app.route("/api/broker/connect", methods=["POST"])
def connect_broker():
    """Save the user's Delta Exchange keys, then immediately test the connection
    by fetching their balance — this is what confirms the keys actually work."""
    data = request.get_json(force=True)
    user_id, api_key, api_secret = data["user_id"], data["api_key"], data["api_secret"]

    client = DeltaExchangeClient(api_key, api_secret)
    try:
        balance = client.get_balance()
    except requests.HTTPError as exc:
        return jsonify({"error": "Could not connect — check your API key/secret", "detail": str(exc)}), 400

    # SECURITY: encrypt api_key/api_secret before saving in a real deployment
    users_col.update_one(
        {"user_id": user_id},
        {"$set": {"broker_creds.delta": {"api_key": api_key, "api_secret": api_secret}}},
    )
    return jsonify({"message": "Connected to Delta Exchange", "balance": balance}), 200


@app.route("/api/broker/balance/<user_id>", methods=["GET"])
def get_broker_balance(user_id):
    user = users_col.find_one({"user_id": user_id})
    creds = (user or {}).get("broker_creds", {}).get("delta")
    if not creds:
        return jsonify({"error": "Broker not connected"}), 400
    client = DeltaExchangeClient(creds["api_key"], creds["api_secret"])
    return jsonify(client.get_balance()), 200


@app.route("/api/broker/trade-history/<user_id>", methods=["GET"])
def get_trade_history(user_id):
    """Supports the same date-range filter as the EasyAlgo Trade History screen:
    /api/broker/trade-history/<user_id>?start=2026-03-05&end=2026-06-05"""
    user = users_col.find_one({"user_id": user_id})
    creds = (user or {}).get("broker_creds", {}).get("delta")
    if not creds:
        return jsonify({"error": "Broker not connected"}), 400

    start_str, end_str = request.args.get("start"), request.args.get("end")
    start_ts = int(datetime.strptime(start_str, "%Y-%m-%d").timestamp()) if start_str else None
    end_ts = int(datetime.strptime(end_str, "%Y-%m-%d").timestamp()) if end_str else None

    client = DeltaExchangeClient(creds["api_key"], creds["api_secret"])
    return jsonify(client.get_order_history(start_ts, end_ts)), 200


# ==============================================================================
# 7. PAYMENTS — Razorpay (this is how Google Pay/UPI/cards all get accepted)
# ==============================================================================
razorpay_client = razorpay.Client(auth=(cfg.RAZORPAY_KEY_ID, cfg.RAZORPAY_KEY_SECRET))


@app.route("/api/payment/create-order", methods=["POST"])
def create_payment_order():
    """Called when the user taps 'Pay & activate' on the Pro-plan screen."""
    data = request.get_json(force=True)
    user_id, amount_inr = data["user_id"], data["amount"]  # e.g. 499

    order = razorpay_client.order.create({
        "amount": amount_inr * 100,  # Razorpay expects paise, not rupees
        "currency": "INR",
        "payment_capture": 1,
    })

    payments_col.insert_one({
        "order_id": order["id"],
        "user_id": user_id,
        "amount": amount_inr,
        "status": "created",
        "created_at": datetime.utcnow(),
    })

    # Send `order["id"]` + your RAZORPAY_KEY_ID to the frontend — Razorpay's
    # checkout widget then shows Google Pay / UPI / cards to the user itself.
    return jsonify(order), 200


@app.route("/api/payment/webhook", methods=["POST"])
def payment_webhook():
    """
    Razorpay calls this URL the moment a payment succeeds or fails, no matter
    which method the user paid with (Google Pay, other UPI apps, card, etc).
    Configure this URL in your Razorpay dashboard -> Webhooks.
    """
    payload = request.get_data()
    signature = request.headers.get("X-Razorpay-Signature", "")

    try:
        razorpay_client.utility.verify_webhook_signature(
            payload.decode(), signature, cfg.RAZORPAY_WEBHOOK_SECRET
        )
    except razorpay.errors.SignatureVerificationError:
        return jsonify({"error": "Invalid webhook signature"}), 400

    event = request.get_json(force=True)
    if event.get("event") == "payment.captured":
        order_id = event["payload"]["payment"]["entity"]["order_id"]
        payment = payments_col.find_one({"order_id": order_id})
        if payment and payment["status"] != "paid":
            payments_col.update_one({"order_id": order_id}, {"$set": {"status": "paid"}})
            # Extend Pro plan by 30 days from now (or from current expiry if still active)
            user = users_col.find_one({"user_id": payment["user_id"]})
            base = user["pro_until"] if user.get("pro_until") and user["pro_until"] > datetime.utcnow() else datetime.utcnow()
            users_col.update_one(
                {"user_id": payment["user_id"]},
                {"$set": {"pro_until": base + timedelta(days=30)}},
            )

    return jsonify({"status": "ok"}), 200


# ==============================================================================
# 8. STRATEGIES — save/list a user's custom strategies (matches the Strategy
#    Builder screen: coin, indicators, timeframe, entry/exit rules, lot size)
# ==============================================================================
@app.route("/api/strategies/<user_id>", methods=["GET"])
def list_strategies(user_id):
    strategies = list(strategies_col.find({"user_id": user_id}, {"_id": 0}))
    return jsonify(strategies), 200


@app.route("/api/strategies/<user_id>", methods=["POST"])
def save_strategy(user_id):
    strategy = request.get_json(force=True)
    strategy["user_id"] = user_id
    strategy["updated_at"] = datetime.utcnow()
    strategies_col.update_one(
        {"user_id": user_id, "id": strategy["id"]},
        {"$set": strategy},
        upsert=True,
    )
    return jsonify({"message": "Strategy saved"}), 200


# ==============================================================================
# 9. RUN
# ==============================================================================
if __name__ == "__main__":
    # debug=True is for local development only — turn it off in production
    app.run(debug=True, port=5000)
