"""Response pacing — making a fast answer land at a plausible wall-clock time.

Response TIME is a side channel. Every deception path on this platform is written
so its text is indistinguishable from a real answer, and then gives itself away
by arriving in 3 milliseconds when a genuine answer takes seconds. A caller who
cannot tell a cover from an answer by reading it can still tell by timing it, and
timing needs no interpretation — it is a number, and the difference is three
orders of magnitude.

So: any path that skips the work a real answer does has to spend the time anyway.

Two callers today, with deliberately different windows:

  * `response_cache` — a cache hit, which skipped the agent call.
  * the orchestrator's deter path — a contained session's answer, which is real
    but cheaper than the specialist agent it claims to come from.

The windows differ because the paths are impersonating different things, so this
module takes the bounds as arguments and holds no policy of its own.

Padding is one-sided ON PURPOSE. `delay_for_window` returns 0 when the request is
already slower than the target: the tell this defends against is answers arriving
suspiciously EARLY, and delaying an already-slow response further would spend
real latency to fix nothing.
"""

from __future__ import annotations

import asyncio
import random


def delay_for_window(
    elapsed_seconds: float, min_seconds: float, max_seconds: float,
) -> float:
    """Seconds to wait so a response lands inside [min, max] total wall-clock.

    Draws a fresh target per call rather than padding to a fixed value. A
    constant total is its own signature — every deterred answer landing at
    exactly 3.00s is more distinctive than one landing at 0.05s, because real
    answers scatter and nothing else on the platform is that punctual.
    """
    lo, hi = min_seconds, max_seconds
    if hi < lo:            # misconfigured env; treat as a single point
        lo, hi = hi, lo
    if hi <= 0:
        return 0.0
    target = random.uniform(lo, hi)
    return max(0.0, target - max(0.0, elapsed_seconds))


async def pace(
    elapsed_seconds: float, min_seconds: float, max_seconds: float,
) -> float:
    """Sleep out the padding. Returns the seconds actually waited.

    asyncio.sleep, so concurrent requests keep being served while this one waits.
    A blocking sleep here would turn a deception feature into a denial of service
    against everyone else on the box.
    """
    delay = delay_for_window(elapsed_seconds, min_seconds, max_seconds)
    if delay > 0:
        await asyncio.sleep(delay)
    return delay
