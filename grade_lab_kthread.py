#!/usr/bin/env python3

import re
import sys
from gradelib import *

r = Runner(save("xv6.out"))

@test(0, "running threadtest")
def test_threadtest():
    r.run_qemu(shell_script([
        'threadtest'
    ]))

@test(10, "threadtest: test1", parent=test_threadtest)
def test_threadtest_test1():
    r.match('^TEST1 PASSED$')

@test(10, "threadtest: test2", parent=test_threadtest)
def test_threadtest_test2():
    r.match('^TEST2 PASSED$')

@test(30, "threadtest: test3", parent=test_threadtest)
def test_threadtest_test3():
    r.match('^TEST3 PASSED$')

@test(10, "threadtest: test4", parent=test_threadtest)
def test_threadtest_test4():
    r.match('^TEST4 PASSED$')

@test(10, "threadtest: test5", parent=test_threadtest)
def test_threadtest_test5():
    r.match('^TEST5 PASSED$')

@test(10, "threadtest: test6", parent=test_threadtest)
def test_threadtest_test6():
    r.match('^TEST6 PASSED$')

@test(5, "threadtest: test7", parent=test_threadtest)
def test_threadtest_test7():
    r.match('^TEST7 PASSED$')

@test(5, "threadtest: test8", parent=test_threadtest)
def test_threadtest_test8():
    r.match('^TEST8 PASSED$')

@test(10, "usertests")
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
