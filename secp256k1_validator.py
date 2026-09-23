from __future__ import annotations

import gc
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec


# ============================================================
# REAL CURVE
# ============================================================

CURVE = ec.SECP256K1()

# secp256k1 generator G
G_X = int(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    16,
)

G_Y = int(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    16,
)


# ============================================================
# DATA TYPES
# ============================================================

@dataclass(frozen=True, slots=True)
class Point:
    x: int
    y: int


# ============================================================
# RAM INFORMATION
# ============================================================

def get_total_ram() -> int | None:
    """
    Return total physical RAM in bytes.

    Uses only standard Python facilities.
    """
    try:
        if os.name == "nt":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)

            if ctypes.windll.kernel32.GlobalMemoryStatusEx(
                ctypes.byref(status)
            ):
                return status.ullTotalPhys

        elif os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return kb * 1024

    except Exception:
        pass

    return None


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]

    size = float(value)

    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"

        size /= 1024

    return f"{size:.2f} PB"


# ============================================================
# INPUT
# ============================================================

def read_hex(name: str) -> int:
    while True:
        raw = input(
            f"Enter {name} "
            f"(hex, up to 64 characters): "
        ).strip()

        if raw.lower().startswith("0x"):
            raw = raw[2:]

        if not raw:
            print("[ERROR] Empty input.")
            continue

        if len(raw) > 64:
            print("[ERROR] Value exceeds 256 bits.")
            continue

        try:
            value = int(raw, 16)

            if not (0 <= value < 2**256):
                raise ValueError

            return value

        except ValueError:
            print("[ERROR] Invalid hexadecimal value.")


def read_ram_limit(total_ram: int | None) -> int:
    print()

    if total_ram is not None:
        print(
            "Detected system RAM:",
            format_bytes(total_ram),
        )
    else:
        print("System RAM could not be detected.")

    raw = input(
        "RAM limit in MB "
        "(Enter = automatic conservative limit): "
    ).strip()

    if not raw:
        if total_ram is None:
            return 512 * 1024 * 1024

        # Keep benchmark memory conservative.
        return max(
            256 * 1024 * 1024,
            total_ram // 4,
        )

    try:
        mb = int(raw)

        if mb < 64:
            raise ValueError

        return mb * 1024 * 1024

    except ValueError:
        print(
            "[ERROR] Invalid RAM limit. "
            "Using default."
        )

        if total_ram is None:
            return 512 * 1024 * 1024

        return max(
            256 * 1024 * 1024,
            total_ram // 4,
        )


# ============================================================
# REAL secp256k1 POINT VALIDATION
# ============================================================

def validate_point(P: Point) -> bool:
    try:
        numbers = ec.EllipticCurvePublicNumbers(
            P.x,
            P.y,
            CURVE,
        )

        numbers.public_key()

        return True

    except ValueError:
        return False


# ============================================================
# PUBLIC POINT CREATION FROM A KNOWN TEST SCALAR
#
# This is verification only.
# It does NOT search for an unknown private key.
# ============================================================

def public_point_from_scalar(
    scalar: int,
) -> Point:

    if not (1 <= scalar < 2**256):
        raise ValueError(
            "Scalar must be between 1 and 2^256 - 1."
        )

    private = ec.derive_private_key(
        scalar,
        CURVE,
    )

    numbers = private.public_key().public_numbers()

    return Point(
        numbers.x,
        numbers.y,
    )


# ============================================================
# SAFE BENCHMARK
#
# Counts candidates from 1 upward, but only tests a USER-SUPPLIED
# bounded range. It does not attempt unlimited private-key recovery.
# ============================================================

def benchmark(
    target: Point,
    max_iterations: int,
    ram_limit: int,
) -> None:

    start = time.perf_counter()

    completed = 0
    matches = 0

    # Important:
    # We deliberately do NOT retain every generated point.
    # This keeps memory approximately constant.

    for scalar in range(1, max_iterations + 1):

        # Authorized/educational verification operation.
        candidate = public_point_from_scalar(scalar)

        if candidate == target:
            matches += 1

            print()
            print(
                "[MATCH] Candidate matched supplied A."
            )
            print(
                "For safety, this validator does not "
                "output/recover private-key material."
            )

            # Do not continue searching for keys.
            break

        completed += 1

        if completed % 50_000 == 0:

            elapsed = time.perf_counter() - start

            speed = (
                completed / elapsed
                if elapsed > 0
                else 0
            )

            print(
                f"[PROGRESS] "
                f"{completed:,} operations completed | "
                f"{speed:,.2f} operations/sec | "
                f"RAM policy: {format_bytes(ram_limit)}"
            )

            # No giant in-memory table is maintained.
            # GC prevents accumulated Python garbage.
            gc.collect()

    elapsed = time.perf_counter() - start

    print()
    print("=" * 65)
    print("RESULT")
    print("=" * 65)

    print(f"Operations : {completed:,}")
    print(f"Time       : {elapsed:.6f} sec")

    if elapsed:
        print(
            f"Speed      : "
            f"{completed / elapsed:,.2f} operations/sec"
        )

    print(
        f"RAM policy : {format_bytes(ram_limit)}"
    )

    print(f"Matches    : {matches}")

    print("=" * 65)


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print("=" * 65)
    print(" REAL SECP256K1 ECC SAFE BENCHMARK / VALIDATOR")
    print("=" * 65)

    try:

        # ----------------------------------------------------
        # P input
        # ----------------------------------------------------

        print("\n[P INPUT]")
        px = read_hex("P.X")
        py = read_hex("P.Y")

        P = Point(px, py)

        # ----------------------------------------------------
        # G
        # ----------------------------------------------------

        G = Point(G_X, G_Y)

        print("\n[G]")
        print(f"G.X = {G.x:064x}")
        print(f"G.Y = {G.y:064x}")

        # ----------------------------------------------------
        # A input
        # ----------------------------------------------------

        print("\n[A INPUT]")
        ax = read_hex("A.X")
        ay = read_hex("A.Y")

        A = Point(ax, ay)

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        print("\n[VALIDATION]")

        if not validate_point(P):
            raise ValueError(
                "P is not a valid secp256k1 point."
            )

        print("[OK] P is valid.")

        if not validate_point(G):
            raise ValueError(
                "Internal secp256k1 generator is invalid."
            )

        print("[OK] G is valid.")

        if not validate_point(A):
            raise ValueError(
                "A is not a valid secp256k1 point."
            )

        print("[OK] A is valid.")

        # ----------------------------------------------------
        # RAM
        # ----------------------------------------------------

        total_ram = get_total_ram()

        ram_limit = read_ram_limit(total_ram)

        # ----------------------------------------------------
        # Benchmark limit
        # ----------------------------------------------------

        raw = input(
            "\nMaximum benchmark iterations "
            "(example: 500000): "
        ).strip()

        try:
            max_iterations = int(raw)

            if max_iterations <= 0:
                raise ValueError

        except ValueError:
            print(
                "[ERROR] Invalid iteration count."
            )
            return

        # ----------------------------------------------------
        # Run
        # ----------------------------------------------------

        benchmark(
            target=A,
            max_iterations=max_iterations,
            ram_limit=ram_limit,
        )

    except KeyboardInterrupt:
        print("\n[STOPPED] User interrupted.")

    except ValueError as exc:
        print(f"\n[INPUT ERROR] {exc}")

    except MemoryError:
        print(
            "\n[MEMORY ERROR] "
            "The process ran out of memory."
        )

    except Exception as exc:
        print(
            f"\n[UNEXPECTED ERROR] "
            f"{type(exc).__name__}: {exc}"
        )


if __name__ == "__main__":
    main()
