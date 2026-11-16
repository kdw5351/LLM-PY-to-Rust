Read the specification below and one condition from its input checklist. Write a small Python program that prints exactly one line of JSON:

{"plus": {"args": {...}}, "minus": {"args": {...}}, "minus_expect": ...}

- "plus": the smallest input that satisfies every condition of the specification, so that the function completes normally and returns a value.
- "minus": the same input changed so that only the condition below is violated. Keep "minus" well-formed: same argument names, same types and same structure as "plus", with every required field present. A program that forgot to check this one condition must still be able to process "minus" normally; only the check for this condition should make the outcome differ.
- "minus_expect": what the specification requires the function to do for "minus". Use {"error": "<ExceptionName>"} if it must raise an exception and the specification names the exception, {"error": true} if it must raise but no name is given, or {"value": <JSON value>} if it must return that exact value. Use {"unspecified": true} only if the specification does not say what happens.
- "args" holds the function's keyword arguments. Encode byte strings as {"__bytes__": "<base64>"}.
- Use only the Python standard library. Do not read or write files and do not use the network. The program must finish within a few seconds.

Reply with exactly one fenced ```python code block.

# Condition

{condition}

# Specification

{spec}
