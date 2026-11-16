Read the specification below and one condition from its input checklist. Write a small Python program that prints exactly one line of JSON:

{"plus": {"args": {...}}, "minus": {"args": {...}}, "minus_expect": ...}

- "plus": the smallest input that satisfies every condition of the specification, so that the function completes normally and returns a value.
- "minus": the same input changed so that only the condition below is violated.
- "minus_expect": what the specification requires the function to do for "minus". Use {"error": true} if it must raise an exception (of any kind), {"value": <JSON value>} if it must return that exact value, or {"unspecified": true} if the specification does not say.
- "args" holds the function's keyword arguments. Encode byte strings as {"__bytes__": "<base64>"}.
- Use only the Python standard library. Do not read or write files and do not use the network. The program must finish within a few seconds.

Reply with exactly one fenced ```python code block.

# Condition

{condition}

# Specification

{spec}
