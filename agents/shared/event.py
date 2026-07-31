# Single source of truth for the public-facing event edition label.
#
# EVENT_EDITION holds the nation + year only (e.g. "USA 2026", "Asia 2026",
# "USA 2027") so next year's iteration is a one-line env change. The static
# "Black Hat" wrapper is composed here into EVENT_LABEL.
#
# This is DISPLAY branding only — it must never be used for S3 prefixes, IAM
# names, or any system config that depends on the frozen "bh-asia-26" naming.
import os

EVENT_EDITION = os.getenv("EVENT_EDITION", "USA 2026").strip()
EVENT_LABEL = f"Black Hat {EVENT_EDITION}"
