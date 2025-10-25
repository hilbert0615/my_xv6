#!/usr/bin/env python3

import re
import sys
import os
from gradelib import *

r = Runner(save("xv6.out"))

PTE_PRINT = """page table 0x0000000087f6e000
 ..0: pte 0x0000000021fda801 pa 0x0000000087f6a000
 .. ..0: pte 0x0000000021fda401 pa 0x0000000087f69000
 .. .. ..0: pte 0x0000000021fdac1f pa 0x0000000087f6b000
 .. .. ..1: pte 0x0000000021fda00f pa 0x0000000087f68000
 .. .. ..2: pte 0x0000000021fd9c1f pa 0x0000000087f67000
 ..255: pte 0x0000000021fdb401 pa 0x0000000087f6d000
 .. ..511: pte 0x0000000021fdb001 pa 0x0000000087f6c000
 .. .. ..510: pte 0x0000000021fdd807 pa 0x0000000087f76000
 .. .. ..511: pte 0x000000002000200b pa 0x0000000080008000"""

VAL_RE = "(0x00000000[0-9a-f]+)"
INDENT_RE = r"\s*\.\.\s*"
INDENT_ESC = "\\\s*\.\.\\\s*"

def remakeFSImage():
    if os.path.exists("fs.img"):
        os.remove("fs.img")
    make("fs.img")

@test(0, "running lazytests")
def test_lazytests():
    r.run_qemu(shell_script([
        'lazytests'
    ]))

@test(10, "lazy: pte printout", parent=test_lazytests)
def test_filetest():
    first = True
    p = re.compile(VAL_RE)
    d = re.compile(INDENT_RE)
    for l in PTE_PRINT.splitlines():
        l = d.sub(INDENT_ESC, l)
        l = p.sub(VAL_RE, l)
        r.match(r'^{}$'.format(l))
        if first:
            first = False
        else:
            matches = re.findall(r'^{}$'.format(l), r.qemu.output, re.MULTILINE)
            assert_equal(len(matches[0]), 2)
            pa = (int(matches[0][0], 16) >> 10) << 12
            assert_equal(int(matches[0][1], 16), pa)

@test(20, "lazy: map", parent=test_lazytests)
def test_filetest():
    r.match("^test lazy unmap: OK$")

@test(20, "lazy: unmap", parent=test_lazytests)
def test_memtest():
    r.match("test lazy alloc: OK$")

def usertest_check(testcase, nextcase):
    remakeFSImage()
    r.run_qemu(shell_script([
        'usertests {}'.format(testcase)
    ]), timeout=30)
    r.match('^ALL TESTS PASSED$')

@test(4, "usertests: pgbug")
def test_pgbug():
    usertest_check("pgbug", "sbrkbugs")

@test(4, "usertests: sbrkbugs")
def test_sbrkbugs():
    usertest_check("sbrkbugs", "badarg")

@test(4, "usertests: argptest")
def test_argptest():
    usertest_check("argptest", "createdelete")

@test(4, "usertests: sbrkmuch")
def test_sbrkmuch():
    usertest_check("sbrkmuch", "kernmem")

@test(4, "usertests: sbrkfail")
def test_sbrkfail():
    usertest_check("sbrkfail", "sbrkarg")

@test(5, "usertests: sbrkarg")
def test_sbrkarg():
    usertest_check("sbrkarg", "validatetest")

@test(5, "usertests: stacktest")
def test_stacktest():
    usertest_check("stacktest", "opentest")

@test(20, "usertests: all tests")
def test_usertests_all():
    remakeFSImage()
    r.run_qemu(shell_script([
        'usertests'
    ]), timeout=300)
    r.match('^ALL TESTS PASSED$')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_tests(outputJSON=sys.argv[1])
    else:
        run_tests()
