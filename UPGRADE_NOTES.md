# EFMS upgrade notes

This package is based on the uploaded EFMS_Final_Fixed project. Existing templates, stylesheet, database, and application modules are retained.

## Changes included in this pass
- Signup no longer asks a new user to select Participant, Volunteer, or Organizer. New self-registered accounts begin as a participant account; volunteer applications can create the linked volunteer record automatically.
- Email verification form now submits the expected `code` field and carries the email address in both verification and resend forms. Resend accepts the form email or query-string email.
- Login now blocks accounts whose email is not verified.
- Password recovery added using a time-limited, one-use email OTP and a new password (the existing password is never emailed).
- Profile photo is shown on the profile page and authenticated sidebar avatar.
- Event hosts are blocked from registering as participants or applying to volunteer for their own event.
- Non-admin event registration is bound to the signed-in account rather than a user ID supplied by the browser.
- Added `password_reset_otps` table automatically through the existing database initialization migration.

## Important configuration
- `.env` is deliberately excluded. Copy `.env.example` to `.env` and set a fresh private secret and your own integration credentials.
- Email verification and password reset require working SMTP. Without SMTP, signup remains unverified and login is blocked.
- Razorpay must use your own test/live credentials. Keep secret keys private. The existing server-side signature verification route is retained.
- Do not deploy publicly without CSRF protection, rate limiting, HTTPS, security review, and verified payment webhook/checkout handling.

## Known remaining work
This pass does not yet complete the full universal-account organizer workflow. New accounts are participant accounts; creating/owning events still uses the existing Organizer/Admin permissions. The volunteer application, review, assignment and inbox routes from the original project are retained, but a complete event-level capability system and end-to-end volunteer assignment acceptance/attendance UI still require a further coordinated upgrade. Existing database roles are retained for backward compatibility.
