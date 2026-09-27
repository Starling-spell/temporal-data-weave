import hashlib
import time

def h(v): return hashlib.sha256(v.encode()).hexdigest()

def test_timeline_guards(direct_vm, direct_deploy, direct_alice, direct_bob):
    c = direct_deploy("contracts/TemporalDataWeave.py")
    direct_vm.sender = direct_alice
    c.create_timeline("demo", "Demo Timeline")
    view = c.get_timeline("demo")
    assert view["version"] == 0 and view["frozen"] is False
    with direct_vm.expect_revert("HTTPS source and SHA-256 required"):
        c.append_state("demo", "obj", "s1", "http://bad", h("x"), "", int(time.time()) + 300)
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("owner required"):
        c.freeze_timeline("demo")
