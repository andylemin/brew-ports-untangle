"""Unit tests of brew-ports, run offline against the fixtures and fakes in this package"""

import os

# A command is printed with its program's bare name when PATH finds that file, so the PATH of the machine that
# runs the tests would decide what they print. No test starts a program, so none needs a PATH.
os.environ["PATH"] = ""
