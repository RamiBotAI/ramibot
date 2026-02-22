.PHONY: dev backend frontend install install-backend install-frontend rami-kali-build rami-kali-start rami-kali-stop rami-kali-logs

dev:
	@echo "Starting backend and frontend..."
	$(MAKE) backend & $(MAKE) frontend & wait

backend:
	cd backend && python -m uvicorn main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

install: install-backend install-frontend

install-backend:
	cd backend && python -m venv .venv && . .venv/Scripts/activate && pip install -r requirements.txt

install-frontend:
	cd frontend && npm install

test:
	cd backend && python -m pytest tests/ -v

RAMIKALI_DIR = rami-kali

rami-kali-build:
	docker build -t rami-kali $(RAMIKALI_DIR)

rami-kali-start:
	docker compose -f $(RAMIKALI_DIR)/docker-compose.yml up -d

rami-kali-stop:
	docker compose -f $(RAMIKALI_DIR)/docker-compose.yml down

rami-kali-logs:
	docker compose -f $(RAMIKALI_DIR)/docker-compose.yml logs -f
