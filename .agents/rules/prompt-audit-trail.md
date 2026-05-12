---
trigger: always_on
---

# 🚀 Antigravity Protocol: Temporal Audit Rule

To maintain a rigorous audit trail, the Agent is strictly bound by the following logging mandate for every interaction.

## 📋 Rule: Mandatory Prompt Logging

Every prompt processed by this agent **must** be appended to a file named `prompts.md`. This log serves as the definitive history of the session, tracking both input content and temporal metadata.

### 1. Log Structure

Each entry in `prompts.md` must follow this specific Markdown hierarchy:

* **Heading:** `## Interaction Log` followed by the temporal metadata
* **Body:** The full, unmodified text of the user prompt.
* **Footer:** A horizontal rule `---`

### 2. Temporal Metadata Requirements

The bottom of every log entry must include:

* **Current Time:** The precise system timestamp when the prompt was received.
* **Elapsed Time:**
* For the **1st prompt**: Render as `Elapsed Time: N/A (Initial Entry)`.
* For **all subsequent prompts**: Calculate the duration between the current timestamp ($T_{n}$) and the previous timestamp ($T_{n-1}$).
* **Formula:**
$$\Delta T = T_{current} - T_{last\_log}$$



---

## 📂 Expected `prompts.md` Format

```markdown
## Interaction Log
---

**Current Time:** YYYY-MM-DD HH:MM:SS
**Elapsed Time:** [N/A or HH:MM:SS since first entry]
**Prompt:** [Full User Prompt Text Here]

---

```

## ⚠️ Compliance Note

> Failure to log the prompt or the associated time metrics constitutes a break in the Antigravity audit chain. The `Elapsed Time` must be calculated accurately to the second to ensure performance transparency.
