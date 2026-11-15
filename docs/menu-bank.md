# Z8 menu-bank, focus shift and framing additions (`bankmode.py`)

This fork adds a separate build script, `bankmode.py`, which patches the official **Nikon Z8 C 3.11** firmware with a set of menu and shooting changes. It is **standalone**: it does not combine with the toolkit's four features (`prores`, `precapture`, `pixelshift`, `opengate-nraw`), because they share menu rows, a menu state and the free text area with each other and with this patch.

**Experimental firmware.** Same warning as the main toolkit: building or installing can cause data loss, card corruption or camera malfunction, and offline checks do not guarantee camera safety. Flash at your own risk. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE.md).

## What it changes

Menu banks
- **Menu bank behavior** row at the end of the Setup menu: choose whether switching shooting menu banks auto-stores the current settings into the bank being left, a "save to bank" command, and **linking** the photo shooting menu bank and the Custom Settings bank so they switch together.
- **Release mode is stored per menu bank**, through the camera's real setting items.
- After a linked switch, both bank changes are announced (fixes a mismatch between the rear and top displays seen on the camera).
- **Bracketing burst button**: while held, bracketing is switched on.

Focus shift shooting
- **End point**: set the current focus position as the end of the series (Focus end point sub-page: Set / Clear). The camera then estimates the number of frames needed to reach it, shown on the focus shift page and on the focus step width slider. The end point is forgotten when the camera goes to standby.
- The focus shift page shows the end point distance and the **current focus distance** (corrected distance scale; estimate up to the lens's infinity position when no end point is set).
- **i menu start**: selecting the *Focus shift shooting* item in the i menu starts the series directly from live view.

Framing grid
- **Custom frame**: Custom Settings > Grid type (photo) gets a sixth entry. Its page sets a **crop factor** from 1.00x to 1.50x (0.05 steps) and an **aspect ratio X:Y** (1–99 each; default 1.00x 3:2 = the whole frame). Live view draws the largest X:Y rectangle centred in the crop area. OK starts / ends editing a value, up / down / the dials change it, back stores it.

## Status

- The menu-bank changes were used on a camera during development (a link defect found there was fixed).
- The focus shift additions and the Custom frame grid are checked offline (independent verifier, instruction-level harness, menus in a QEMU emulator) but are **not camera-tested**. The emulator never draws the framing grid, so the Custom frame rectangle itself has only been checked by the harness.
- A test raising Multiple exposure above 10 shots froze the camera ("busy") and was reverted; it is not in the current build.

## Build and verify

Requirements: Python 3.10+, `requirements.txt` (Capstone), and `llvm-objdump` for the verifier.

```sh
python bankmode.py "/path/to/Z_8_0311.bin" --version 04.20 --tag d0 --output build/bank
python verify_bankmode.py "/path/to/Z_8_0311.bin" build/bank/Z_8_0420.bin --version 04.20 --tag d0
```

With version 04.20 and tag d0 the output should be `Z_8_0420.bin` with SHA-256 `b8323e3f71ec6c865a9bb64b4440567b9c6a968f00582ae590f4cdf802b20f7a`. Tags are a lowercase letter plus a digit. Build from the official input each time; the output directory must not exist.

Developer harness (runs the patch code under QEMU against stubs; needs clang, ld.lld and qemu-system-aarch64):

```sh
python tests/bankmode_harness/run_harness.py --qemu /path/to/qemu-system-aarch64
python tests/bankmode_harness/run_harness.py --qemu /path/to/qemu-system-aarch64 --mutate <name>   # each mutation must fail
```

No Nikon firmware, patched firmware or extracted firmware data is included in this repository; obtain the official input from Nikon yourself.
