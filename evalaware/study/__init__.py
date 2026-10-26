"""Agent study: do LLM agents probe for, notice, or react to being in a sandbox?

WARNING: this package executes model-chosen shell commands. Run it only inside a disposable
sandbox (container/VM with no credentials and restricted egress). It refuses to execute unless
allow_exec=True / --allow-exec is passed explicitly.
"""
