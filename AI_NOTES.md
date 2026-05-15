# AI Notes

---

## How Claude Was Used

Claude was used as a staged implementer rather than a free-form assistant. The workflow
for each approach was to provide a self-contained phase prompt describing exactly what to
build, review the output manually before accepting it, and feed any corrections or questions
back as follow-up messages before moving to the next phase.

For Approach B this meant five sequential phases. Phase 1 established the cryptographic
infrastructure and directory skeleton. Phases 2 and 3 implemented the receiver and sender
respectively. Phase 4 handled Docker orchestration. Phase 5 produced the four documentation
files. Each phase was treated as a checkpoint where the output was read and tested before
proceeding.

Claude was also used reactively throughout. When a bug surfaced in testing or a design
concern was identified the specific issue was described to Claude and the proposed fix was
reviewed before being accepted. Claude was not given open-ended authority to refactor or
extend code outside the scope of the question being asked.

---

## How Other Tools Were Used

**Gemini Plus** was used before any coding began. It processed the assessment brief and the
checklist PDF to evaluate trade-offs between the two architectural approaches and produced
the specification document and staged prompt structure that Claude then executed.

**GitHub Copilot** was used as a passive reviewer inside the IDE during and after
implementation. It provided inline suggestions during editing and was used for a final review
pass over both approaches before submission.
