---
name: Accept-invitation stale useEffect after submit
description: Why AcceptInvitationPage showed "Invitation has already been used" even after a successful 201 from accept-invitation.
---

## The rule
After `POST /api/auth/accept-invitation` succeeds, guard the `useEffect` catch handler against setting `loadError` by using a `useRef` that tracks successful submission.

## Why
React (in development/Strict Mode) or an app-level re-bootstrap (GET /api/auth/me triggered by Zustand login state change) can cause the `invitation-info` useEffect to re-run after the token is already consumed. The re-run returns 410 (token used), which without the guard overwrites the success state and shows the "Invitation Error" screen — even though the user was already logged in and the redirect timer was running.

## How to apply
Pattern used in `AcceptInvitationPage.tsx`:

```tsx
const submittedRef = useRef(false);

useEffect(() => {
  apiFetch(`/api/auth/invitation-info?token=...`)
    .catch(err => {
      if (!submittedRef.current) {   // ← guard here
        setLoadError(err?.message ?? "Invalid or expired invitation link.");
      }
    });
}, [token]);

// In handleSubmit success branch:
submittedRef.current = true;   // ← set BEFORE setDone(true)
setDone(true);
```

A `useRef` is required (not `useState`) because the catch callback closes over a stale value; refs are mutable and always reflect the latest value.
