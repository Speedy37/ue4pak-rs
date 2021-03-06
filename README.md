# ue4pak - Unreal Engine 4 .pak file encoder/decoder

Supported versions:

-   [x] `PakFile_Version_Initial = 1`
-   [x] `PakFile_Version_NoTimestamps = 2`
-   [x] `PakFile_Version_CompressionEncryption = 3`
-   [x] `PakFile_Version_IndexEncryption = 4`
-   [x] `PakFile_Version_RelativeChunkOffsets = 5`
-   [x] `PakFile_Version_DeleteRecords = 6`
-   [x] `PakFile_Version_EncryptionKeyGuid = 7`
-   [x] `PakFile_Version_FNameBasedCompressionMethod = 8` (≤ UE4.22)
-   [x] `PakFile_Version_FNameBasedCompressionMethod = 8` (≥ UE4.23)
-   [x] `PakFile_Version_FrozenIndex = 9`
-   [x] `PakFile_Version_PathHashIndex = 10` (UE4.26)
-   [x] `PakFile_Version_Fnv64BugFix = 11`

Supported features:

-   [ ] compression
-   [x] decryption
-   [x] encryption
-   [ ] frozen index (UE4.26 dropped the code, so I don't plan to support it)

Documentation: https://speedy37.github.io/ue4pak-rs/ue4pak/index.html
