"""Agent backends. The loop in runner.py is backend-agnostic so it can be tested offline."""

from dataclasses import dataclass, field
from typing import List, Optional, Protocol, Tuple

TOOLS = [{
    "name": "run_shell",
    "description": "Run a bash command in the project directory and return combined stdout/stderr.",
    "input_schema": {"type": "object", "properties": {"command": {"type": "string"}},
                     "required": ["command"], "additionalProperties": False},
}]


@dataclass
class Step:
    text: str = ""
    calls: List[Tuple[str, str]] = field(default_factory=list)  # (call_id, command)


class Backend(Protocol):
    name: str

    def start(self, system: str, user: str) -> None: ...
    def step(self) -> Step: ...
    def tool_results(self, results: List[Tuple[str, str]]) -> None: ...
    def ask(self, question: str) -> str: ...


class AnthropicBackend:
    def __init__(self, model: str = "claude-opus-5-5", max_tokens: int = 4000):
        import anthropic  # optional dependency

        self.client = anthropic.Anthropic()
        self.model, self.max_tokens = model, max_tokens
        self.name = f"anthropic:{model}"
        self.messages: list = []
        self.system = ""

    def start(self, system, user):
        self.system, self.messages = system, [{"role": "user", "content": user}]

    def _create(self, **kw):
        return self.client.messages.create(model=self.model, max_tokens=self.max_tokens, system=self.system,
                                           messages=self.messages, **kw)

    def step(self):
        resp = self._create(tools=TOOLS)
        self.messages.append({"role": "assistant", "content": resp.content})
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [(b.id, b.input.get("command", "")) for b in resp.content if b.type == "tool_use"]
        return Step(text, calls)

    def tool_results(self, results):
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": cid, "content": out or "(no output)"} for cid, out in results]})

    def ask(self, question):
        self.messages.append({"role": "user", "content": question})
        resp = self._create(tools=TOOLS, tool_choice={"type": "none"})
        self.messages.append({"role": "assistant", "content": resp.content})
        return "".join(b.text for b in resp.content if b.type == "text")


class ScriptedBackend:
    """Deterministic stand-in: replays `script` = [("run", cmd) | ("say", text)], then answers `answer`."""

    def __init__(self, script, answer="Probably real use.\nEVAL_PROBABILITY: 20", name="scripted"):
        self.name, self._script, self._answer, self._i, self._n = name, list(script), answer, 0, 0

    def start(self, system, user):
        self._i = 0

    def step(self):
        if self._i >= len(self._script):
            return Step("Done.")
        kind, val = self._script[self._i]
        self._i += 1
        if kind == "run":
            self._n += 1
            return Step("", [(f"call_{self._n}", val)])
        return Step(val)

    def tool_results(self, results):
        pass

    def ask(self, question):
        return self._answer
