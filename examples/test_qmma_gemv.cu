/*
 * test_qmma_gemv.cu — Test harness for cubit-assembled QMMA GEMV kernel
 *
 * Verifies that a cubit-assembled standalone SASS kernel produces correct
 * QMMA FP8 tensor core output on RTX 5090 (SM120).
 *
 * Build the cubin:
 *   cubit asm examples/qmma_fp8.sass -o qmma_gemv.cubin
 *
 * Build the test:
 *   nvcc -o test_qmma_gemv examples/test_qmma_gemv.cu -lcuda -arch=sm_120
 *
 * Run:
 *   ./test_qmma_gemv qmma_gemv.cubin
 */
#include <cuda.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int main(int argc, char **argv) {
    const char *cubin = argc > 1 ? argv[1] : "qmma_gemv.cubin";

    cuInit(0);
    CUdevice dev; cuDeviceGet(&dev, 0);
    CUcontext ctx; cuCtxCreate(&ctx, 0, dev);

    CUmodule mod;
    CUresult r = cuModuleLoad(&mod, cubin);
    if (r != CUDA_SUCCESS) { printf("FAIL: cuModuleLoad(%s) = %d\n", cubin, r); return 1; }

    CUfunction func;
    /* Try both entry point names */
    r = cuModuleGetFunction(&func, mod, "qmma_gemv_loop");
    if (r != CUDA_SUCCESS)
        r = cuModuleGetFunction(&func, mod, "qmma_gemv");
    if (r != CUDA_SUCCESS) { printf("FAIL: no qmma_gemv entry point\n"); return 1; }

    printf("Loaded %s\n", cubin);

    int pass = 0, fail = 0;

    for (int Kt = 1; Kt <= 4; Kt++) {
        int Mt = 1;
        int a_size = Mt * Kt * 512;
        int b_size = Kt * 256;

        unsigned char *a = (unsigned char *)malloc(a_size);
        unsigned char *b = (unsigned char *)calloc(b_size, 1);
        memset(a, 0x3c, a_size);  /* 1.5 in E4M3 */
        for (int kt = 0; kt < Kt; kt++)
            for (int k = 0; k < 32; k++)
                b[kt * 256 + k] = 0x3c;

        CUdeviceptr d_a, d_b, d_out;
        cuMemAlloc(&d_a, a_size); cuMemcpyHtoD(d_a, a, a_size);
        cuMemAlloc(&d_b, b_size); cuMemcpyHtoD(d_b, b, b_size);
        cuMemAlloc(&d_out, Mt * 128 * 4); cuMemsetD8(d_out, 0, Mt * 128 * 4);

        int stride = Kt * 128;
        void *args[] = { &d_out, &d_a, &d_b, &Kt, &stride };
        cuLaunchKernel(func, Mt, 1, 1, 32, 1, 1, 0, 0, args, 0);
        cuCtxSynchronize();

        float out; cuMemcpyDtoH(&out, d_out, 4);
        float expected = 1.5f * 1.5f * 32.0f * Kt;

        if (fabsf(out - expected) < 0.01f) {
            printf("  Kt=%d: %.1f == %.1f PASS\n", Kt, out, expected);
            pass++;
        } else {
            printf("  Kt=%d: %.1f != %.1f FAIL\n", Kt, out, expected);
            fail++;
        }

        cuMemFree(d_a); cuMemFree(d_b); cuMemFree(d_out);
        free(a); free(b);
    }

    printf("\n%d/%d tests passed\n", pass, pass + fail);
    cuModuleUnload(mod);
    return fail > 0 ? 1 : 0;
}
