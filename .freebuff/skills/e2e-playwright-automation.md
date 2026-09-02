---
name: e2e-playwright-automation
description: >-
  Write resilient end-to-end (E2E) web and mobile tests using Playwright, Page Object Model (POM),
  network mocking, visual regression testing, and CI parallelization.
  Use when automating browser tests, testing critical user flows, or verifying UI regressions.
---

# Playwright E2E Test Automation Master

This skill provides industry standards for creating flake-free, fast, and maintainable end-to-end browser tests using Playwright and the Page Object Model.

---

## 🎭 E2E Testing Architecture

```mermaid
graph TD
    TestRunner[Playwright Test Runner - Parallel Workers] --> POM[Page Object Models: LoginPage, CheckoutPage]
    POM --> Locators[Resilient User-Facing Locators: getByRole, getByLabel]
    Locators --> Browser[Headless Chromium / Firefox / WebKit]
    Browser --> APIIntercept[Route Mocking / API Interception]
    TestRunner --> Artifacts[Trace Viewer, Video & Screenshots on Failure]
```

---

## 🎯 Production Invariants

1. **User-Facing Locators Only**: Always use `page.getByRole()`, `page.getByLabel()`, and `page.getByText()`. Never use fragile CSS/XPath selectors like `div > span:nth-child(3)`.
2. **Auto-Waiting**: Never insert arbitrary `page.waitForTimeout(5000)`. Rely on Playwright's built-in web-first assertions (`await expect(locator).toBeVisible()`).
3. **Trace on Retry**: Always enable `trace: 'on-first-retry'` to inspect complete DOM snapshots and network logs on test failures.

---

## 📋 Prosedur Eksekusi

1. **Pola Page Object Model (POM)**:
   - Baca [references/page-object-model.md](./references/page-object-model.md).
2. **Template Test Spec**:
   - Terapkan kode dari [resources/login.spec.ts](./resources/login.spec.ts).
3. **Jalankan Test di CI**:
   - Jalankan `bash skills/e2e-playwright-automation/scripts/run-playwright-ci.sh`.