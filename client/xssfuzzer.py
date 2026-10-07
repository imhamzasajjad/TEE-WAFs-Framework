"""Small, syntax-preserving-ish XSS payload mutator.

The fuzzer changes representation and context around an existing payload; it
does not execute JavaScript.  It is intentionally conservative so that the
original payload remains recognizable in benchmark logs.
"""

import random
import re


def _random_text(length=6):
    alphabet = "xX sS tT 0123456789".replace(" ", "")
    return "".join(random.choice(alphabet) for _ in range(length))


def tag_case(payload):
    """Randomise the case of HTML tag names and closing-tag markers."""
    tag_pattern = re.compile(r"(<\/?)([A-Za-z][\w:-]*)")

    def replace(match):
        name = "".join(c.upper() if random.random() < 0.5 else c.lower()
                       for c in match.group(2))
        return match.group(1) + name

    return tag_pattern.sub(replace, payload)


def comments_injection(payload):
    """Insert an HTML comment at a safe boundary or before a closing tag."""
    comment = "<!--" + _random_text() + "-->"
    closing = re.search(r"</[A-Za-z][^>]*>", payload)
    if closing:
        position = random.choice([closing.start(), closing.end()])
    else:
        position = random.randrange(len(payload) + 1)
    return payload[:position] + comment + payload[position:]


def comments_rewriting(payload):
    """Rewrite an existing HTML/JavaScript comment, if one is present."""
    patterns = [r"<!--.*?-->", r"/\*.*?\*/", r"//[^\r\n]*"]
    for pattern in patterns:
        if re.search(pattern, payload, flags=re.DOTALL):
            return re.sub(pattern, "<!--" + _random_text() + "-->", payload,
                          count=1, flags=re.DOTALL)
    return payload


def invariant_tags(payload):
    """Wrap a payload in a harmless-looking inline HTML element."""
    tag = random.choice(["b", "span", "i", "div"])
    return f"<{tag}>{payload}</{tag}>"


def attribute_context(payload):
    """Place a JavaScript body into an HTML attribute context.

    This creates test strings only; the fuzzer never renders or executes them.
    A script body is extracted when the input is a script element so that the
    generated attribute remains syntactically meaningful.
    """
    script_match = re.search(
        r"<script(?:\s[^>]*)?>(.*?)</script>",
        payload,
        flags=re.IGNORECASE | re.DOTALL,
    )
    body = script_match.group(1).strip() if script_match else payload.strip()
    if not body:
        return payload

    # Keep quote characters from prematurely terminating the generated value.
    attribute_body = body.replace('"', "&quot;").replace("'", "&#39;")
    variants = [
        f'<img src="x" onerror="{attribute_body}">',
        f'<svg onload="{attribute_body}"></svg>',
        f'<a href="javascript:{attribute_body}">link</a>',
    ]
    return random.choice(variants)


def js_comments_injection(payload):
    """Add a JavaScript comment around whitespace or an expression boundary."""
    if re.search(r"\s+", payload):
        return re.sub(r"\s+", "/**/", payload, count=1)
    return payload


def js_argument_rewrite(payload):
    """Replace a numeric function argument with an equivalent expression.

    Every generated expression evaluates to the original integer.  This keeps
    the mutation focused on representation rather than changing the argument's
    value or type.
    """
    function_pattern = re.compile(r"\b(alert|confirm|prompt)\s*\(([^()]*)\)", re.I)
    match = function_pattern.search(payload)
    if not match:
        return payload

    argument = match.group(2).strip()
    if not re.fullmatch(r"[+-]?\d+", argument):
        return payload

    value = int(argument)
    offset = random.randint(1, 9)
    equivalents = [
        f"({value}+0)",
        f"({value}-0)",
        f"({value}*1)",
        f"({value}/1)",
        f"(({value}+{offset})-{offset})",
        f"({value}+({offset}-{offset}))",
    ]
    replacement = f"{match.group(1)}{random.choice(equivalents)}"
    return payload[:match.start()] + replacement + payload[match.end():]


def js_function_alias(payload):
    """Use an equivalent common JavaScript call where possible."""
    replacements = {
        "alert": ["window.alert", "globalThis.alert"],
        "confirm": ["window.confirm", "globalThis.confirm"],
        "prompt": ["window.prompt", "globalThis.prompt"],
    }
    pattern = re.compile(r"\b(alert|confirm|prompt)(?=\s*\()", re.I)
    return pattern.sub(lambda m: random.choice(replacements[m.group(1).lower()]), payload, count=1)


def js_operator_rewrite(payload):
    """Reserved for context-aware operator mutations.

    JavaScript operators such as ``==``/``===`` and ``&&``/``&`` are not
    generally equivalent, so this strategy intentionally leaves the payload
    unchanged until an expression-aware implementation is available.
    """
    return payload


class XssFuzzer:
    """Generate bounded, compounded XSS representations.

    Each round starts from the original payload and applies a short random
    chain of operators (not a single one), so that many rounds explore
    distinct variants instead of collapsing onto a handful of wrappers.
    Emitted variants are de-duplicated within a run, and every chain is
    validated structurally before it is returned.
    """

    strategies = [
        tag_case,
        comments_injection,
        comments_rewriting,
        invariant_tags,
        attribute_context,
        js_comments_injection,
        js_argument_rewrite,
        js_function_alias,
    ]

    def __init__(self, payload, max_length=2048, max_chain=4, max_attempts=16):
        self.initial_payload = payload
        self.payload = payload
        self.max_length = max(128, int(max_length))
        self.max_chain = max(1, min(int(max_chain), len(self.strategies)))
        self.max_attempts = max(1, int(max_attempts))
        self._emitted = set()
        self.last_operator = ''
        self.last_validation = ''

    def _choose_chain(self):
        """Pick a short, ordered chain of distinct operators to compound."""
        length = random.randint(1, self.max_chain)
        pool = list(self.strategies)
        random.shuffle(pool)
        return pool[:length]

    @staticmethod
    def _validate(payload):
        """Perform conservative structural checks; do not execute the payload."""
        if not payload or not payload.strip():
            return False, 'empty'
        if any(ord(char) < 9 for char in payload):
            return False, 'control-character'
        # Unescaped quote imbalance commonly produces a non-meaningful
        # attribute value. HTML entities are unaffected by this check.
        for quote in ('"', "'"):
            escaped = re.sub(r'\\' + re.escape(quote), '', payload)
            if escaped.count(quote) % 2:
                return False, f'unbalanced-{quote}-quote'
        # A candidate should retain either an executable/context marker or a
        # script-like marker from the source representation.
        marker = re.compile(
            r'<\s*(?:script|svg|img|iframe)|on(?:error|load|click)\s*=|'
            r'javascript\s*:|\b(?:alert|confirm|prompt|eval)\s*\(', re.I
        )
        if not marker.search(payload):
            return False, 'no-xss-context'
        return True, 'ok'

    def fuzz(self):
        # Make several attempts to produce a *fresh*, valid, in-bounds variant
        # by compounding a short chain of operators. Compounding (rather than a
        # single operator) and de-duplication together stop the output from
        # collapsing onto a few repeated wrappers across many rounds.
        fallback = None
        fallback_operators = ''
        last_reason = 'no-valid-mutation'
        for _ in range(self.max_attempts):
            chain = self._choose_chain()
            candidate = self.initial_payload
            for strategy in chain:
                candidate = strategy(candidate)
            names = '+'.join(strategy.__name__ for strategy in chain)

            if len(candidate) > self.max_length:
                last_reason = f'rejected-length>{self.max_length}'
                continue
            if candidate == self.initial_payload:
                last_reason = 'rejected-unchanged'
                continue
            valid, reason = self._validate(candidate)
            if not valid:
                last_reason = f'rejected-{reason}'
                continue
            if candidate not in self._emitted:
                self._emitted.add(candidate)
                self.payload = candidate
                self.last_operator = names
                self.last_validation = 'ok'
                return candidate
            # Valid but already produced this run: keep it as a fallback and
            # keep trying for something new.
            fallback = candidate
            fallback_operators = names
            last_reason = 'duplicate'

        if fallback is not None:
            self.payload = fallback
            self.last_operator = fallback_operators
            self.last_validation = 'ok-duplicate'
            return fallback

        # No operator chain produced a valid variant. Keep the source visible
        # in the log rather than sending an invalid synthetic payload.
        self.last_operator = 'none'
        self.last_validation = (
            'no-valid-mutation' if last_reason == 'duplicate' else last_reason
        )
        self.payload = self.initial_payload
        return self.payload

    def current(self):
        return self.payload

    def reset(self):
        self.payload = self.initial_payload
        return self.payload
