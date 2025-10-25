import re
import sys
from gradelib import *

r = Runner(save("xv6.out"))

@test(20, "sleep, no args")
def test_sleep_no_args():
    r.run_qemu(shell_script([
        'sleep'
    ]))
    r.match(no=["exec .* failed", "$ sleep\n$"])

@test(20, "sleep, returns")
def test_sleep_echo():
    r.run_qemu(shell_script([
        'sleep',
        'echo OK'
    ]))
    r.match('^OK$', no=["exec .* failed", "$ sleep\n$"])

@test(10, "sleep, makes syscall")
def test_sleep_breakpoint():
    r.run_qemu(shell_script([
        'sleep 10',
        'echo FAIL'
    ]), stop_breakpoint('sys_sleep'))
    r.match('\\$ sleep 10', no=['FAIL'])

@test(20, "countsys, simple")
def test_countsys_simple():
    r.run_qemu(shell_script([
        'countsys',
    ]))
    r.match('4[12345]', no=["exec .* failed"])

@test(20, "countsys, twice")
def test_countsys_twice():
    r.run_qemu(shell_script([
        'countsys',
        'countsys',
    ]))
    r.match('6[12345]', no=["exec .* failed"])

@test(10, "countsys, sleep 10, countsys")
def test_countsys_sleep():
    r.run_qemu(shell_script([
        'sleep 10',
        'countsys',
    ]))
    r.match('(5[89]|6[012])', no=["exec .* failed"])

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_tests(outputJSON=sys.argv[1])
    else:
        run_tests()

