# Notes

- User preference: quiz answer choices must all be the same word count
  (and character count where possible) — no formatting-based hints toward
  the correct answer.
- `MISSION-FORMAT.md`, `RESOURCES-FORMAT.md`, and `LEARNING-RECORD-FORMAT.md`
  referenced by the `teach` skill weren't present in this session, so
  `MISSION.md`/`RESOURCES.md` were drafted freehand. If those format files
  turn up later (or the user defines them), reconcile the existing docs to
  match rather than leaving two conventions.
- This workspace lives inside `iam-engine/teach/`, not as a sibling project —
  explicit user placement choice, so teaching material travels with the code
  it's about.
- `disable-model-invocation: true` on the `teach` skill means I should never
  auto-trigger `/teach` myself; the user invokes it explicitly.
