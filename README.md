# Honeypot CAPTCHA

A proof-of-concept **honeypot CAPTCHA** web application built with Flask.
It logs request data (IP, User-Agent, timestamp) both locally (as NDJSON) and optionally to AWS CloudWatch Logs.

The purpose of this application is to demonstrate the following security concepts:
* Implementation and utilization of simple CAPTCHA on a webpage.
* Ability to record client information and secure log storage.
* Demonstration of secure coding practices. (Preventative measures against hardcoded secrets, injection attacks, and the implementation of rate limiting).
* Configuration of AWS IAM roles, EC2 Security Groups, and CloudWatch logs.

**Disclaimer:** This project is for educational/demo purposes only. It should not be used as a production CAPTCHA solution.

---

## Features

* Simple CAPTCHA system (random 6-character alphanumeric).
* Logs requests locally to `/var/log/honeypot/honeypot.ndjson`.
* Optional CloudWatch Logs integration.
* Basic security headers via `flask-talisman`.
* Optional request rate limiting via `flask-limiter`.

---

## Requirements

* Python 3.9+
* Dependencies listed in `requirements.txt`:

```txt
Flask==3.0.3  
Werkzeug==3.0.3  
flask-limiter==3.8.0  
flask-talisman==1.1.0  
boto3==1.34.162  
botocore==1.34.162  
python-dotenv==1.0.1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

Environment variables can be set in a `.env` file (see `.env.example`):

| Variable             | Default Value                       | Description                                |
| -------------------- | ----------------------------------- | ------------------------------------------ |
| `FLASK_SECRET_KEY`   | random on startup                   | Flask session secret key                   |
| `HP_LOG_PATH`        | `/var/log/honeypot/honeypot.ndjson` | Local log file path                        |
| `HP_AWS_LOGS_ENABLE` | `false`                             | Enable CloudWatch logging (`true`/`false`) |
| `AWS_REGION`         | `us-west-1`                         | AWS region                                 |
| `HP_AWS_LOG_GROUP`   | `honeypot-captcha`                  | CloudWatch Log Group                       |
| `HP_AWS_LOG_STREAM`  | `requests`                          | CloudWatch Log Stream                      |

---

## Running Locally

```bash
export FLASK_SECRET_KEY="super-secret-key"
export HP_AWS_LOGS_ENABLE="false"   # or "true" if AWS configured
python app.py
```

Then visit: [http://localhost:5000](http://localhost:5000)

---

## Deployment on AWS EC2

### 1. Launch EC2 Instance

* Amazon Linux 2023 or Ubuntu 22.04 recommended.
* Allow inbound traffic on port **5000** (or **80/443** if using Nginx).

### 2. Connect to the instance

```bash
ssh -i your-key.pem ec2-user@your-ec2-public-ip
```

### 3. Install dependencies

Amazon Linux:

```bash
sudo yum update -y
sudo yum install git python3 python3-pip -y
```

Ubuntu:

```bash
sudo apt-get update -y
sudo apt-get install git python3 python3-pip -y
```

### 4. Clone and set up the app

```bash
git clone <your-repo-url> honeypot-captcha
cd honeypot-captcha
pip3 install -r requirements.txt
```

### 5. Configure environment

Create `.env` file:

```bash
nano .env
```

Example:

```env
FLASK_SECRET_KEY=super-secret-key
HP_AWS_LOGS_ENABLE=true
AWS_REGION=us-west-1
```

### 6. Run the app

```bash
python3 app.py
```

The app will run on:
`http://<EC2_PUBLIC_IP>:5000`

---

## (Optional) Run with Gunicorn + Nginx

For production:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Configure **Nginx** as a reverse proxy to serve on ports **80/443**.

---

## Auto-start with systemd (recommended)

To run the app automatically on EC2 reboot, create a **systemd service file**:

1. Create the service file:

```bash
sudo nano /etc/systemd/system/honeypot.service
```

2. Paste the following configuration (adjust paths as needed):

```ini
[Unit]
Description=Honeypot CAPTCHA Flask App
After=network.target

[Service]
User=ec2-user
WorkingDirectory=/home/ec2-user/honeypot-captcha
Environment="FLASK_SECRET_KEY=super-secret-key"
EnvironmentFile=/home/ec2-user/honeypot-captcha/.env
ExecStart=/usr/bin/python3 /home/ec2-user/honeypot-captcha/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

3. Reload systemd and start service:

```bash
sudo systemctl daemon-reload
sudo systemctl start honeypot
sudo systemctl enable honeypot
```

4. Check logs:

```bash
sudo journalctl -u honeypot -f
```

Now the app will automatically start on reboot.

---

## Logs

* Local logs: `/var/log/honeypot/honeypot.ndjson`
* CloudWatch Logs (if enabled): `honeypot-captcha/requests`

---

## Known Issues
* The CloudWatch logs don't update their entry number field correctly, will work out why later. I'll probably have some secondary or auxiliary program to parse through these logs and sort them for ingestion, but it's not a high priority at the moment.
* There are some IPv4 issues when connecting via a web browser. Or it could be HTTPS/HSTS issues. Regardless, my solution was to just register it onto a public domain with proper security headers and certifications. It shouldn't be an issue if you're running it locally.
