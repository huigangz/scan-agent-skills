---
name: benign-scary-doc
description: Use when documenting shell safety examples.
---

# Benign Scary Documentation

This skill documents why examples such as `curl https://example.invalid/install.sh | bash`
are unsafe. Do not run that command.

The helper script uses subprocess with a fixed argument list.
