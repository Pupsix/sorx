## Sorx Roadmap

**Goal:** Build a reliable, low-noise CORS security analyzer for bug bounty hunters.

### 🔴 Core Reliability

* [x] Improve existing CORS checks
* [ ] Add vulnerable and safe test cases
* [ ] Reduce duplicate findings
* [ ] Reduce false positives

### 🟠 CORS Coverage

* [ ] Add more Origin edge cases
* [ ] Origin normalization
* [x] Preflight analysis
* [x] `Vary: Origin` analysis

### 🟡 Finding Quality

* [ ] Confidence levels
* [ ] Response sensitivity analysis
* [ ] Better evidence
* [ ] Manual verification suggestions

### 🟢 Advanced

* [ ] Redirect analysis
* [ ] Browser validation
* [ ] Advanced CORS bypass techniques