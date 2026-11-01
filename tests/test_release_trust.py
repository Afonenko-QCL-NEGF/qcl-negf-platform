"""Local real FD/ownership/path cleanup controls; no installed-site proof."""
from pathlib import Path
import os
import stat
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
import release_trust as trust


@pytest.mark.parametrize('kind',[MemoryError,KeyboardInterrupt,RuntimeError])
@pytest.mark.parametrize('phase',['entry','body'])
def test_directory_primary_identity_survives_real_closed_then_raises(monkeypatch,kind,phase):
    primary=kind('original '+phase);close=os.close;opened=os.open;fds=[];closed=[];calls=[]
    class Budget:
        def before(self):
            calls.append(True)
            if phase=='entry' and len(calls)==2:raise primary
    def opening(*args,**kw):
        fd=opened(*args,**kw);fds.append(fd);return fd
    def closing(fd):
        close(fd);closed.append(fd)
        with pytest.raises(OSError):os.fstat(fd)
        raise OSError('secondary directory close')
    monkeypatch.setattr(trust.os,'open',opening);monkeypatch.setattr(trust.os,'close',closing)
    with pytest.raises(kind) as caught:
        with trust.protected_directory('/',budget=Budget()):raise primary
    assert caught.value is primary and fds==closed
    assert getattr(primary,'__notes__',[]) and all(len(note)<=256 for note in primary.__notes__)


def test_following_fd_is_owned_before_previous_close_can_fail_without_retry(monkeypatch):
    close=os.close;opened=os.open;fds=[];attempts=[];primary=OSError('original prior directory close')
    def opening(*args,**kw):
        fd=opened(*args,**kw);fds.append(fd);return fd
    def closing(fd):
        attempts.append(fd);close(fd)
        if fd==fds[0]:raise primary
    monkeypatch.setattr(trust.os,'open',opening);monkeypatch.setattr(trust.os,'close',closing)
    try:
        with pytest.raises(OSError) as caught:
            with trust.protected_directory('/proc'):pytest.fail('body entered after old close failed')
        assert caught.value is primary
        assert len(fds)==2 and attempts==fds
        for fd in fds:
            with pytest.raises(OSError):os.fstat(fd)
    finally:
        # Only our test's acquired descriptors; repair the demonstrated baseline
        # leak after recording the failure, so RED leaves no dangling own FD.
        for fd in fds:
            try:os.fstat(fd)
            except OSError:continue
            close(fd)


def test_healthy_directory_close_failure_is_visible(monkeypatch):
    close=os.close;primary=OSError('healthy body, failed close');fds=[]
    def closing(fd):
        close(fd);fds.append(fd)
        with pytest.raises(OSError):os.fstat(fd)
        raise primary
    monkeypatch.setattr(trust.os,'close',closing)
    with pytest.raises(OSError) as caught:
        with trust.protected_directory('/') as fd:assert stat.S_ISDIR(os.fstat(fd).st_mode)
    assert caught.value is primary and fds==[fd]


@pytest.mark.parametrize('kind',[None,MemoryError,KeyboardInterrupt,RuntimeError])
@pytest.mark.parametrize('outer_close',[False,True])
def test_read_protected_file_preserves_primary_through_leaf_and_directory(monkeypatch,kind,outer_close):
    close=os.close;read=os.read;primary=None if kind is None else kind('original protected metadata read')
    secondary=OSError('leaf close failure');leaf={'fd':None,'entered':False};closed=[]
    def reading(fd,size):
        leaf.update(fd=fd,entered=True)
        if primary is not None:raise primary
        return read(fd,size)
    def closing(fd):
        is_leaf=leaf['fd']==fd;is_outer=outer_close and leaf['entered'] and stat.S_ISDIR(os.fstat(fd).st_mode)
        close(fd)
        with pytest.raises(OSError):os.fstat(fd)
        if is_leaf:leaf['fd']=None;closed.append('leaf');raise secondary
        if is_outer:closed.append('outer');raise OSError('secondary directory close')
    monkeypatch.setattr(trust.os,'read',reading);monkeypatch.setattr(trust.os,'close',closing)
    with pytest.raises(kind or OSError) as caught:trust.read_protected_file('/proc/sys/kernel/osrelease')
    assert caught.value is (primary or secondary) and closed==(['leaf','outer'] if outer_close else ['leaf'])
    assert all(len(note)<=256 for note in getattr(caught.value,'__notes__',[]))


@pytest.mark.parametrize('path',['relative','/proc/../etc','/proc//sys','/proc/self'])
def test_path_and_nofollow_refusals_are_retained(path):
    with pytest.raises((ValueError,OSError)):
        with trust.protected_directory(path):pytest.fail('unsafe path admitted')


def test_real_root_owner_mode_type_and_budget_paths_are_unchanged(tmp_path):
    for p in ('/proc','/proc/sys'):
        with trust.protected_directory(p) as fd:trust.trusted_stat(os.fstat(fd),directory=True)
    with pytest.raises(ValueError):
        with trust.protected_directory(tmp_path):pytest.fail('mutable/unprivileged ancestry admitted')
    raw=trust.read_protected_file('/proc/sys/kernel/osrelease',256)
    assert 0<len(raw)<=256
