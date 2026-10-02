# This file is part of the Trezor project.
#
# Copyright (C) SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

"""Trezor Safe 5 (T3T1) — single-file model definition."""

import hashlib

from . import HashParams, KeySet, Layout, ModelClass, ModelData, keys
from ._shared import TREZOR_CORE_DEV

MODEL = ModelData(
    internal_name="T3T1",
    name="Safe 5",
    hw_model=b"T3T1",
    minimum_version=(2, 7, 2),
    aliases=("safe5", "s5"),
    model_class=ModelClass.CORE,
    layout=Layout.DELIZIA,
    ble_capable=False,
    # The aylo authenticator's own keys, replacing SatoshiLabs' for this project.
    # These must stay equal to MODEL_BOARDLOADER_KEYS and MODEL_BOOTLOADER_KEYS in
    # core/embed/models/T3T1/model_T3T1.h: the C side decides what the device accepts
    # and this side decides what headertool and audit_image report, so if they drift
    # the tools call a good image invalid, or worse call a bad one valid. root_keys.h
    # says the same thing about its own pair of lists.
    prod_keys=KeySet(
        production=True,
        boardloader_keys=keys(
            "7cfd63aaa1994671b92de7370109ec7bd4f0497a76579ee6d6c65649a7f57fb2",
            "bad3746ec834191047e94f5f3755655d6864e58c849a9fc1d7d74b9e3c4b78b4",
            "7d094e145978f769658621e64e78849f5fddd49f37c01a7a942b2483ead36bb6",
        ),
        boardloader_sigs_needed=2,
        bootloader_keys=keys(
            "aa1737dfdab207ff95ba42e03a1d377b8f5b700df76d297652b1e309c4fc5b8d",
            "8e798e39cce1b11902e6c9444b05cf38c3ffbb282fdb527c36a70483b7856031",
            "fa77d38502010565433e56c00180ad6280ee0707678b7861f937ac63c01eaffb",
        ),
        bootloader_sigs_needed=2,
    ),
    dev_keys=TREZOR_CORE_DEV,
    hash_params=HashParams(
        hash_function=hashlib.sha256,
        chunk_size=1024 * 128,
        padding_byte=None,
    ),
)
