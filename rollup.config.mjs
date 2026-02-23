import typescript from "rollup-plugin-typescript2";
import commonjs from "@rollup/plugin-commonjs";
import nodeResolve from "@rollup/plugin-node-resolve";
import {minify} from "rollup-plugin-esbuild-minify";

export default [
    // IIFE bundle (single-file JavaScript bundle for HTML5 web apps)
    {
        input: "src/index.ts",
        output: {
            file: "dist/tinypki-client-side-cert-req-lib.js",
            format: "iife",
            name: "TinyPKIClientSideCertReqLib",
            sourcemap: true,
        },
        plugins: [
            nodeResolve({
                browser: true,
                preferBuiltins: false,
            }),
            commonjs(),
            typescript({
                clean: true,
                tsconfigOverride: {
                    compilerOptions: {
                        module: "ES2020",
                    },
                },
            }),
            minify()
        ],
    },
    // TypeScript ESM + declaration files
    {
        input: "src/index.ts",
        output: {
            file: "dist/index.js",
            format: "esm",
            sourcemap: true,
        },
        plugins: [
            nodeResolve({
                browser: true,
                preferBuiltins: false,
            }),
            commonjs(),
            typescript({
                clean: true,
                useTsconfigDeclarationDir: true,
                tsconfigOverride: {
                    compilerOptions: {
                        module: "ES2020",
                        declaration: true,
                        declarationDir: "dist/types",
                        outDir: "dist",
                    },
                },
            }),
        ],
    },
];
