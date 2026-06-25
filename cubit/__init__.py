"""cubit — SM120 CUDA assembler: encode, decode, patch SASS instructions."""
try:
    # When installed as a package, the native extension is cubit.cubit
    from .cubit import *  # noqa: F401,F403
    __doc__ = cubit.__doc__
    if hasattr(cubit, "__all__"):
        __all__ = cubit.__all__
except ImportError:
    # Running from source tree without maturin develop — native ext not yet built
    pass
