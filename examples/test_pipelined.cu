/*
 * test_pipelined.cu — Test cubit-assembled pipelined QMMA GEMV kernel
 *
 * Build cubin:   cubit asm examples/qmma_pipelined.sass -o pipelined.cubin
 * Build test:    nvcc -o test_pipelined examples/test_pipelined.cu -lcuda -arch=sm_120
 * Run:           ./test_pipelined pipelined.cubin
 */
#include <cuda.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int main(int argc, char **argv) {
    const char *cubin = argc > 1 ? argv[1] : "pipelined.cubin";
    int max_kt = argc > 2 ? atoi(argv[2]) : 8;

    cuInit(0);
    CUdevice dev; cuDeviceGet(&dev, 0);
    CUcontext ctx;
#if CUDA_VERSION >= 13000
    /* CUDA 13+: cuCtxCreate maps to v4. Use runtime API instead —
     * driver API v4 creates contexts that break desc[] in standalone cubins */
    cudaSetDevice(0); cudaFree(0);
    cuCtxGetCurrent(&ctx);
#else
    cuCtxCreate(&ctx, 0, dev);
#endif

    CUmodule mod;
    CUresult r = cuModuleLoad(&mod, cubin);
    if (r != CUDA_SUCCESS) { printf("FAIL: cuModuleLoad(%s) = %d\n", cubin, r); return 1; }

    CUfunction func;
    r = cuModuleGetFunction(&func, mod, "qmma_gemv_pipelined");
    if (r != CUDA_SUCCESS) {
        r = cuModuleGetFunction(&func, mod, "qmma_gemv_loop");
        if (r != CUDA_SUCCESS) {
            r = cuModuleGetFunction(&func, mod, "qmma_gemv");
            if (r != CUDA_SUCCESS) { printf("FAIL: no entry point found\n"); return 1; }
        }
    }

    printf("Loaded %s, testing Kt=1..%d\n", cubin, max_kt);

    int pass = 0, fail = 0;

    for (int Kt = 1; Kt <= max_kt; Kt++) {
        int Mt = 1;
        /* A matrix: Mt*Kt tiles, each tile = 16 rows * 32 cols = 512 bytes (FP8) */
        int a_size = Mt * Kt * 512;
        /* B vector: Kt tiles, each tile = 256 bytes (8 columns * 32 rows) */
        int b_size = Kt * 256;

        unsigned char *a = (unsigned char *)malloc(a_size);
        unsigned char *b = (unsigned char *)calloc(b_size, 1);

        /* Fill A with 1.5 in E4M3 (0x3c) */
        memset(a, 0x3c, a_size);

        /* Fill ALL B bytes with 0x3c (all columns non-zero) */
        memset(b, 0x3c, b_size);

        CUdeviceptr d_a, d_b, d_out;
        cuMemAlloc(&d_a, a_size); cuMemcpyHtoD(d_a, a, a_size);
        cuMemAlloc(&d_b, b_size); cuMemcpyHtoD(d_b, b, b_size);
        cuMemAlloc(&d_out, Mt * 128 * 4); cuMemsetD8(d_out, 0, Mt * 128 * 4);

        int stride = Kt * 128;
        void *args[] = { &d_out, &d_a, &d_b, &Kt, &stride };
        r = cuLaunchKernel(func, Mt, 1, 1, 32, 1, 1, 0, 0, args, 0);
        if (r != CUDA_SUCCESS) {
            printf("  Kt=%d: LAUNCH FAIL (%d)\n", Kt, r);
            fail++;
        } else {
            CUresult sr = cuCtxSynchronize();
            if (sr != CUDA_SUCCESS) {
                const char *err = "?";
                cuGetErrorString(sr, &err);
                printf("  Kt=%2d: SYNC ERROR %d (%s)\n", Kt, sr, err);
                fail++;
                cuMemFree(d_a); cuMemFree(d_b); cuMemFree(d_out);
                free(a); free(b);
                continue;
            }

            /* Read all 4 output elements (QMMA produces 4 per lane) */
            float out[4];
            cuMemcpyDtoH(out, d_out, 16);

            /* Expected: each element = 1.5 * 1.5 * 32 * Kt = 72 * Kt */
            float expected = 1.5f * 1.5f * 32.0f * Kt;

            /* Only check out[0] — other columns have zero B data */
            int ok = (fabsf(out[0] - expected) < 0.5f);

            if (ok) {
                printf("  Kt=%2d: %.1f == %.1f  PASS\n", Kt, out[0], expected);
                pass++;
            } else {
                printf("  Kt=%2d: %.1f != %.1f  FAIL  [%.1f, %.1f, %.1f, %.1f]\n",
                       Kt, out[0], expected, out[0], out[1], out[2], out[3]);
                fail++;
            }
        }

        cuMemFree(d_a); cuMemFree(d_b); cuMemFree(d_out);
        free(a); free(b);
    }

    printf("\n%d/%d tests passed\n", pass, pass + fail);
    cuModuleUnload(mod);
    return fail > 0 ? 1 : 0;
}
