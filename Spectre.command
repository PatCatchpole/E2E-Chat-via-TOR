#!/bin/bash
# Double-click this in Finder to start Spectre.
#
# macOS runs a .command file by opening Terminal in the user's home directory,
# not next to the file, so the first job is to find our own directory. The rest
# is picking an interpreter: the project venv if it exists, otherwise whatever
# python3 is on the path.

cd "$(dirname "$0")" || exit 1

if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    echo "Python 3 was not found. Install it from https://www.python.org/downloads/"
    echo
    read -r -p "Press Return to close this window."
    exit 1
fi

"$PYTHON" spectre.py
STATUS=$?

# Terminal closes the window on exit and takes the error with it, so anything
# that went wrong needs to be held on screen deliberately.
if [ $STATUS -ne 0 ]; then
    echo
    echo "Spectre exited with status $STATUS."
    read -r -p "Press Return to close this window."
fi
