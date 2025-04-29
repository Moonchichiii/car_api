# 🚗 Car Rental API

> A lean, Django REST backend for vehicle bookings and user management.

- **Frontend Repository**: (https://github.com/Moonchichiii/car_client)

---

## 📋 Table of Contents

- [✨ Overview](#-overview)  
- [🛠️ Tech](#️-tech)  
- [📂 Structure](#-structure)  
- [⚡ Features](#-features)  
- [🚦 Quickstart](#-quickstart)  
- [🧪 Tests](#-tests)  
- [📊 Diagram](#-diagram)  
- [🛣️ Roadmap](#-roadmap)  

---

## ✨ Overview

A single-settings Django project with decoupled apps, JWT auth, PostGIS support, Redis/Celery, and Cloudinary media.  
[🔝 Back to top](#-table-of-contents)

---

## 🛠️ Tech

- **Django 5.x**, DRF  
- **PostgreSQL + PostGIS**  
- **JWT** (HTTP-only cookies)  
- **Redis & Celery**  
- **Cloudinary**  
- **i18n** (EN/FR)  
[🔝 Back to top](#-table-of-contents)

---

## 📂 Structure

```plaintext
car_rental_api/
├── config/        # settings.py, urls.py, asgi.py, wsgi.py
├── apps/
│   ├── core/      # utils & middleware
│   ├── users/     # User model & auth
│   ├── vehicles/  # Vehicle CRUD
│   ├── bookings/  # Booking logic
│   └── payments/  # Stripe webhooks
├── locale/        # translations
├── .env/.env.example
├── manage.py
└── requirements.txt
🔝 Back to top

⚡ Features
Email-based JWT auth

Google OAuth

Vehicle & booking CRUD

PostGIS radius search

Cloudinary uploads
🔝 Back to top

🚦 Quickstart
bash

git clone <repo>
cd car_rental_api
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # fill in values
python manage.py migrate
python manage.py runserver
# celery -A config worker -l info  (optional)
🔝 Back to top

🧪 Tests
Unit & integration

bash
pytest
Load testing

bash
locust -f tests/locust/locustfile.py
# open http://localhost:8089
🔝 Back to top

📊 Diagram
<details> <summary>Select diagram</summary>
Choose one:
<select>

<option value="class">Class Diagram</option> <option value="er">ER Diagram</option> </select>
mermaid
<img src="class-diagram.webp"></img>

</details> [🔝 Back to top](#-table-of-contents)
🛣️ Roadmap
Auth & user setup

Vehicle & booking APIs

Webhooks & media

Geolocation & maps

Testing & deployment
🔝 Back to top
