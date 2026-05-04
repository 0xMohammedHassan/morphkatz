// Target rule for morphkatz - identifies the residual signatures in
// our amsi_patch_demo binary so morphkatz can attempt to mutate them.
// Used with `morphkatz --target tests/samples/amsi_demo_target.yar`.

rule AmsiPatch_Constants {
    meta:
        author = "morphkatz-test"
        description = "AmsiScanBuffer patch (E_INVALIDARG + ret) and the API/library names"
    strings:
        $patch         = { B8 57 00 07 80 C3 }            // mov eax,80070057h ; ret
        $amsi_dll      = "amsi.dll" ascii
        $amsi_function = "AmsiScanBuffer" ascii
    condition:
        any of them
}
