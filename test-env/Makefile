# ZiggySpiderweb Test Environment Makefile

.PHONY: help build up down shell test wipe logs status test-embed-multi-service test-distributed-workspace test-distributed-workspace-bootstrap test-distributed-workspace-drift test-distributed-workspace-matrix test-distributed-workspace-encrypted test-distributed-workspace-operator-token test-distributed-soak-chaos

help: ## Show this help message
	@echo "ZiggySpiderweb Test Environment"
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the test Docker image
	docker-compose build

up: ## Start the test container
	docker-compose up -d

down: ## Stop and remove the test container
	docker-compose down

shell: ## Enter the running test container
	docker exec -it spiderweb-test bash

test: ## Run automated tests in the container
	docker exec -it spiderweb-test /home/spiderweb/ziggy-spiderweb-src/test-env/test-install.sh

wipe: ## Completely wipe and restart (destroys all data)
	docker-compose down --rmi local --volumes
	docker-compose up --build -d

logs: ## View container logs
	docker-compose logs -f

status: ## Check container status
	docker-compose ps

# Quick test scenarios
quick-test: build up ## Build, start, and enter container
	@echo "Container started. Entering shell..."
	@docker exec -it spiderweb-test bash

install-test: build up ## Test the install script
	@echo "Testing install script..."
	@docker exec -it spiderweb-test bash -c "curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh | bash"

local-install-test: build up ## Test local install.sh
	@echo "Testing local install.sh..."
	@docker exec -it spiderweb-test bash -c "cd /home/spiderweb/ziggy-spiderweb-src && ./install.sh"

test-embed-multi-service: ## Run local embedded multi-service integration test
	@bash ./test-embed-multi-service.sh

test-distributed-workspace: ## Run distributed workspace failover integration test
	@bash ./test-distributed-workspace.sh

test-distributed-workspace-bootstrap: ## Run distributed workspace project_up bootstrap scenario
	@bash ./test-distributed-workspace-bootstrap.sh

test-distributed-workspace-drift: ## Run distributed workspace drift/reconcile scenario
	@bash ./test-distributed-workspace-drift.sh

test-distributed-workspace-matrix: ## Run distributed workspace matrix (failover/reconnect/bootstrap/drift)
	@bash ./test-distributed-workspace-matrix.sh

test-distributed-workspace-encrypted: ## Run distributed workspace test with encrypted control-plane persistence
	@bash ./test-distributed-workspace-encrypted.sh

test-distributed-workspace-operator-token: ## Run distributed workspace test with operator-token gate assertions
	@bash ./test-distributed-workspace-operator-token.sh

test-distributed-soak-chaos: ## Run long-running distributed workspace soak/chaos suite
	@bash ./test-distributed-soak-chaos.sh
