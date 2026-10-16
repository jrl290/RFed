"""Write lxmf_1_1_1_locally_processed.bin: the file LXMF 1.1.1 keeps its
locally processed transient ids in.

LXMRouter.exit_handler saves it with save_locally_processed_transient_ids, a
msgpack map of each id to the float time it was received. This runs LXMF's own
save_locally_processed_transient_ids on a stand-in for the router that holds
only what it reads. The rfed test
`locally_processed_tests::reads_the_file_lxmf_writes` loads it.

Run with the workspace venv (LXMF 1.1.1):
    .venv/bin/python RFed-rust/rfed/tests/fixtures/lxmf_locally_processed_fixture.py
"""

import os
import shutil
import tempfile

import LXMF
from LXMF.LXMRouter import LXMRouter

assert LXMF.__version__ == "1.1.1", LXMF.__version__


class Router:
    def __init__(self, storagepath):
        self.storagepath = storagepath
        self.locally_processed_transient_ids = {
            bytes([0x11] * 32): 1760000000.75,
            bytes([0x22] * 32): 1760086400.5,
            bytes([0x33] * 32): 1760172800.25,
        }


storage = tempfile.mkdtemp()
LXMRouter.save_locally_processed_transient_ids(Router(storage))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lxmf_1_1_1_locally_processed.bin")
shutil.copyfile(os.path.join(storage, "locally_processed"), out)
shutil.rmtree(storage)
print(out)
