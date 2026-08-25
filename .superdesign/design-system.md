# Health Intake — Design System

## Product and job to be done

`Профиль здоровья` is a protected Russian-language intake flow for a nutrition professional. A client arrives via a personal invitation, confirms access by email code, completes a long health-and-lifestyle questionnaire, saves progress automatically, reviews the result, and submits it for a personal consultation.

The interface must make a 46-question form feel calm, finite, private, and respectful. It is not a generic form builder, a public survey, or a clinical dashboard. Do not imply diagnosis or emergency medical advice.

## Core UX flow

1. Invitation landing: explain confidentiality, approximate duration, and what happens next. Include an unchecked required consent checkbox before the primary action: `Я согласен(на) на обработку персональных данных и данных о состоянии здоровья для подготовки персональных рекомендаций`, plus a visible `Политика конфиденциальности` link. This is a design placeholder: the final legal wording and policy URL must be approved before production.
2. Email access: client enters or confirms their email; no password creation.
3. One-time-code verification: six-digit code, resend state, clear error/retry feedback.
4. Questionnaire shell: autosave, progress, back/next controls, pause-and-return reassurance.
5. Ten themed sections: Personal data; Lifestyle; Goals and motivation; Health history; Nutrition; GI and wellbeing; Sleep and stress; Gender-specific health; Physical activity and habits; Readiness and final details.
6. Review: compact section-by-section summary with edit links.
7. Completion: confirmation, what happens next, and a read-only submission state.
8. Error states: expired invitation, revoked invitation, invalid/expired code, upload failure, and offline/autosave retry.

## Questionnaire interaction rules

- Keep questions grouped by the ten source sections. Do not show 46 isolated pages.
- The invitation screen blocks `Начать анкету` until the consent checkbox is checked. It has a clear inline error state, a focusable policy link, and no preselected consent.
- Each section has 2–7 airy question cards and a single clear primary action: `Продолжить`.
- Render source `Множественный выбор` as radio cards; source `Флажки` as multi-select chips/cards.
- Selecting `Да (уточните)` or `Другое` reveals an optional, labelled clarification field directly below the answer.
- Show the female-specific question only after `Женский`; the male-specific question only after `Мужской`. For other or undisclosed gender values, do not force either field.
- Preserve source hints as helper text below fields, never as the only placeholder.
- Height and weight use numeric fields with units. `Дата рождения / возраст` starts with a choice between birth date and age, then presents the matching input.
- Stress and readiness are tactile 0–10 / 1–10 scales with selected value announced in text, not colour alone.
- File uploads are optional and visibly separated from ordinary answers. Include selected-file state, remove action, privacy note, and upload progress.
- Autosave after meaningful field changes; show `Сохранено`, `Сохраняем…`, or `Не удалось сохранить — повторить`.
- The final submit action validates only visible required fields and makes the completed questionnaire read-only.

## Visual direction

Primary inspiration: the Superdesign library style `softly-digital-wellness-app`, adapted into a more mature editorial health product. The result should feel like a thoughtful private consultation notebook, not a pastel wellness landing page and not a cold hospital portal.

No real brand asset has been supplied. Use the plain-text wordmark `Профиль здоровья`; do not invent a logo mark, initials badge, or fake medical symbol.

### Palette

- Paper background: `#F6F2EA`
- Surface: `#FFFCF6`
- Ink: `#173A34`
- Secondary ink: `#5D6863`
- Sage: `#DCE6D8`
- Peach clay accent: `#C97554`
- Soft peach: `#F3D8CB`
- Line: `#DED8CD`
- Calm success: `#4D7A65`
- Error: `#A34D42`

Use ink and paper as the dominant contrast. Use clay only for actions, selected states, and small moments of warmth. Never introduce purple gradients, saturated neon, generic blue SaaS accents, or glossy glass cards.

### Typography

- Display: `Cormorant Garamond` for section titles and rare reflective emphasis.
- Interface/body: `Manrope` for all questions, helper text, controls, and data.
- Use Russian sentence case. Avoid all-caps headings except tiny metadata labels.

### Layout and composition

- Desktop: a quiet 280px left progress rail and one wide, centred questionnaire column (`max-width: 960px`) in the remaining viewport. The real form is never placed in a narrow right rail and there is no decorative mobile-preview column in the production layout.
- Mobile: sticky top progress with current section, a naturally scrollable single-column form, 16px page padding, and a bottom action bar that never hides the active input. Do not use fixed-height form canvases or clipped question cards.
- Cards: 18px radius, 1px warm border, almost no shadow; selected answers use ink/sage/clay contrast, not a heavy box shadow.
- The first screen may use an asymmetric editorial composition. Data-entry screens remain intentionally calm and legible.

### Motion and feedback

- Page/section transition: 180–240ms opacity and 8px vertical movement.
- Reveal a dependent clarification field with a short height/opacity transition.
- Progress updates smoothly but respect `prefers-reduced-motion`.
- Do not use floating decorative blobs, distracting parallax, or long animations inside the questionnaire.

## Accessibility and trust

- Every input has a persistent visible label and associated helper/error text.
- Use semantic fieldsets and legends for radio/checkbox groups. In card-style groups, keep the native `legend` visually hidden and render its matching visible question as the first text block inside the card; a question title must never sit on or interrupt the fieldset border.
- Radio groups must use one native `input[type="radio"]` name and derive selected styling only from `peer-checked`; never hardcode selected classes on an option.
- Optional comment or clarification fields stay visible after the question regardless of the selected answer, including `Нет`; never hide them with selection-dependent JavaScript.
- Keyboard focus is clearly visible in clay or ink; never communicate status by colour alone.
- The welcome and file-upload screens explain confidentiality in plain Russian.
- The UI must work at 320px width and remain usable with browser zoom.

## Draft target

Create the base desktop-and-mobile questionnaire shell showing the active `Питание` section, the left progress rail on desktop, three representative question types, autosave state, and the emotional tone of a private guided intake. Include a small responsive mobile frame in the same design board so the system can be reviewed before generating sibling flow screens.
