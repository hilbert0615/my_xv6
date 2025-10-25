#!/usr/bin/env python3

import re
import sys
from gradelib import *

r = Runner(save("xv6.out"))

@test(0, "running alarmtest")
def test_alarmtest():
    r.run_qemu(shell_script([
        'alarmtest'
    ]))

@test(30, "alarmtest: test0", parent=test_alarmtest)
def test_alarmtest_test0():
    r.match('^test0 passed$')

@test(40, "alarmtest: test1", parent=test_alarmtest)
def test_alarmtest_test1():
    r.match('^\\.?test1 passed$')

@test(10, "alarmtest: test2", parent=test_alarmtest)
def test_alarmtest_test2():
    r.match('^\\.?test2 passed$')

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