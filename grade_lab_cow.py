#!/usr/bin/env python3

import re
import sys
from gradelib import *

r = Runner(save("xv6.out"))

@test(0, "running cowtest")
def test_cowtest():
    r.run_qemu(shell_script([
        'cowtest'
    ]),timeout=300)

@test(30, "simple", parent=test_cowtest)
def test_simple():
    matches = re.findall("^simple: ok$", r.qemu.output, re.M)
    assert_equal(len(matches), 2, "Number of appearances of 'simple: ok'")

@test(30, "three", parent=test_cowtest)
def test_three():
    matches = re.findall("^three: ok$", r.qemu.output, re.M)
    assert_equal(len(matches), 3, "Number of appearances of 'three: ok'")

@test(20, "file", parent=test_cowtest)
def test_file():
    r.match('^file: ok$')

@test(20, "usertests")
def test_usertests():
    r.run_qemu(shell_script([
        'usertests'
    ]), timeout=300)
    r.match('^ALL TESTS PASSED$')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_tests(outputJSON=sys.argv[1])
    else:
        run_tests()
