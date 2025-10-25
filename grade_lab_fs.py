#!/usr/bin/env python3

import re
import sys
from gradelib import *

r = Runner(save("xv6.out"))

@test(0, "running special file test")
def test_special():
    r.run_qemu(shell_script([
        'specialtest'
    ]))

@test(15, "test /dev/null", parent=test_special)
def test_devnull():
    r.match('^SUCCESS: test /dev/null$', no=["exec .* failed"])

@test(15, "test /dev/zero", parent=test_special)
def test_devnull():
    r.match('^SUCCESS: test /dev/zero$', no=["exec .* failed"])

@test(15, "test /dev/uptime", parent=test_special)
def test_devnull():
    r.match('^SUCCESS: test /dev/uptime$', no=["exec .* failed"])

@test(15, "test /dev/random", parent=test_special)
def test_devnull():
    r.match('^SUCCESS: test /dev/random$', no=["exec .* failed"])

@test(20, "test symlinks")
def test_devnull():
    r.run_qemu(shell_script([
        'symlinktest'
    ]))
    r.match('^SUCCESS: test symlinks$', no=["exec .* failed"])

@test(15, "test large files (extra credit)")
def test_largefiletest():
    r.run_qemu(shell_script([
        'largefiletest'
    ]), timeout=300)
    r.match('^passed$', no=["exec .* failed"])

@test(20, "usertests")
def test_usertests():
    r.run_qemu(shell_script([
        'usertests'
    ]), timeout=500)
    r.match('^ALL TESTS PASSED$')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_tests(outputJSON=sys.argv[1])
    else:
        run_tests()
