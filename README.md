# 🚗 Car Rental API

> A lean, Django REST backend for vehicle bookings and user management.

- **Frontend Repository**: [Car Client](https://github.com/Moonchichiii/car_client)

---

## 📋 Table of Contents

- [✨ Overview](#-overview)  
- [🛠️ Tech](#️-tech)  
- [📂 Structure](#-structure)  
- [⚡ Features](#-features)  
- [🚦 Quickstart](#-quickstart)  
- [🧪 Tests](#-tests)  
- [📊 Diagram](#-diagram)  
- [🛣️ Roadmap](#️-roadmap)  

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
```

[🔝 Back to top](#-table-of-contents)

## ⚡ Features

- Email-based JWT auth
- Google OAuth
- Vehicle & booking CRUD
- PostGIS radius search
- Cloudinary uploads

[🔝 Back to top](#-table-of-contents)

## 🚦 Quickstart

```bash
git clone <repo>
cd car_rental_api
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # fill in values
python manage.py migrate
python manage.py runserver
# celery -A config worker -l info  (optional)
```

[🔝 Back to top](#-table-of-contents)

## 🧪 Tests

### Unit & integration

```bash
pytest
```

### Load testing

```bash
locust -f tests/locust/locustfile.py
# open http://localhost:8089
```

[🔝 Back to top](#-table-of-contents)

## 📊 Diagram

**Diagram Options:**

- [Class Diagram](class-diagram.webp)
- [ER Diagram](er-diagram.webp)

![Class Diagram](class-diagram.webp)

[🔝 Back to top](#-table-of-contents)

## 🛣️ Roadmap

1. Auth & user setup
2. Vehicle & booking APIs
3. Webhooks & media
4. Geolocation & maps
5. Testing & deployment

[🔝 Back to top](#-table-of-contents)
