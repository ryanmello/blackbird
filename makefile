docker-up:
	@echo "Starting Docker containers in dev mode..."
	docker-compose up --build -d

docker-down:
	@echo "Stopping Docker containers..."
	docker-compose down
