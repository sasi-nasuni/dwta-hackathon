INSTANCE ?= dwta1
UV := uv run

.PHONY: help setup lint test acceptance lab-init lab-up lab-down lab-reset lab-status corpus demo review clean

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

setup:           ## create .venv with every workspace package + dev tools
	uv sync --all-packages

lint:            ## ruff
	$(UV) ruff check .

test:            ## unit tests (no Docker needed)
	$(UV) pytest -m "not lab"

acceptance:      ## end-to-end dwell-window story on a throwaway lab instance (Docker)
	$(UV) pytest tests/acceptance -m lab -p no:warnings

lab-init:        ## create lab/$(INSTANCE)/ (.env, secrets, folders)
	$(UV) dwta-lab -i $(INSTANCE) init

lab-up:          ## build images and start the lab
	$(UV) dwta-lab -i $(INSTANCE) up

lab-down:        ## stop the lab
	$(UV) dwta-lab -i $(INSTANCE) down

lab-reset:       ## wipe lab state (keeps .env and secrets)
	$(UV) dwta-lab -i $(INSTANCE) reset

lab-status:      ## container status
	$(UV) dwta-lab -i $(INSTANCE) status

corpus:          ## build the default corpus pack (once)
	$(UV) dwta-sim corpus build

demo: corpus     ## run the dwell-window scenario on $(INSTANCE)
	$(UV) dwta-sim -i $(INSTANCE) run dwell-window

review:          ## show the latest incident's pre-restore review list
	@I=$$(ls -t lab/$(INSTANCE)/run/incidents | head -1); \
	$(UV) dwta-lab -i $(INSTANCE) compose exec -T incident dwta-incident show $$I

clean:           ## remove caches
	find . -name __pycache__ -type d -prune -exec rm -rf {} +; rm -rf .pytest_cache .ruff_cache
