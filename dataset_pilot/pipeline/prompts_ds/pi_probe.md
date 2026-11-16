Read the specification below and one condition from its input checklist. Write a small Python program that prints exactly one line of JSON with two inputs for the function:

{"plus": {"args": {...}}, "minus": {"args": {...}}}

- "plus": the smallest input that satisfies every condition of the specification, so that the function completes normally.
- "minus": the same input changed so that only the condition below is violated.
- "args" holds the function's keyword arguments. Encode byte strings as {"__bytes__": "<base64>"}.
- Use only the Python standard library. Do not read or write files and do not use the network. The program must finish within a few seconds.

Reply with exactly one fenced ```python code block.

# Condition

{condition}

# Specification

{spec}
