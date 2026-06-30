"""
DEV-ONLY helper: runs the real main.py FastAPI app on port 8000 (matching
the dashboard's hardcoded API_BASE), stubbing only the BERT model load -
the trained weights (model.safetensors) are not present in this checkout,
only config.json/tokenizer.json. Everything else (risk_scoring engine,
link checks, DMARC/IPQS calls, DB writes) runs as real code.

Replace the stub once you have the real model weights:
delete this file and run `uvicorn main:app --reload --port 8000` instead.
"""
import math
import torch

STUB_KEYWORDS = [
    "urgent", "verify", "suspend", "click here", "wire transfer",
    "password", "confidential", "act now", "limited time", "login now",
]


class _FakeTokenizerOutput(dict):
    def to(self, *a, **k):
        return self


class _FakeTokenizer:
    def __call__(self, text, **kwargs):
        self._last_text = text or ""
        return _FakeTokenizerOutput(
            input_ids=torch.zeros((1, 4), dtype=torch.long),
            attention_mask=torch.ones((1, 4), dtype=torch.long),
        )


_shared_tokenizer = _FakeTokenizer()


class _FakeOutput:
    def __init__(self, logits):
        self.logits = logits


class _FakeModel:
    def eval(self):
        return self

    def __call__(self, **kwargs):
        text = _shared_tokenizer._last_text.lower()
        hits = sum(1 for kw in STUB_KEYWORDS if kw in text)
        p1 = min(0.05 + hits * 0.18, 0.97)
        p0 = 1 - p1
        logit0, logit1 = math.log(p0 + 1e-9), math.log(p1 + 1e-9)
        return _FakeOutput(torch.tensor([[logit0, logit1]]))


import transformers
transformers.AutoTokenizer.from_pretrained = staticmethod(lambda *a, **k: _shared_tokenizer)
transformers.AutoModelForSequenceClassification.from_pretrained = staticmethod(lambda *a, **k: _FakeModel())

import uvicorn
import main  # noqa: E402

if __name__ == "__main__":
    print("\n*** DEV STUB: BERT model is FAKE (keyword heuristic), not the trained model ***\n")
    uvicorn.run(main.app, host="127.0.0.1", port=8000, log_level="info")
