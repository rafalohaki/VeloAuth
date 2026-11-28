# Third-party notices

VeloAuth is distributed under the license in [LICENSE](LICENSE). Its embedded-limbo feature also
uses the following independently maintained software. This notice is informational and does not
replace the license text supplied by each upstream project.

## MCProtocolLib

- Project: [GeyserMC/MCProtocolLib](https://github.com/GeyserMC/MCProtocolLib)
- Artifact: `org.geysermc.mcprotocollib:protocol:26.3-4`
- SHA-256: `aac3344ae89b14d1dca961ff462532c4b75a7da42a4c73c470535e7c17a97874`
- License: [MIT](https://github.com/GeyserMC/MCProtocolLib/blob/master/LICENSE.txt)
- Use in VeloAuth: shaded and package-relocated network engine for the loopback-only embedded
  listener. Netty is not bundled or relocated; Velocity supplies the shared Netty runtime.

MCProtocolLib brings the following package-relocated runtime dependencies into the VeloAuth JAR:

- MCProtocolLib `text-serializer-nbt` `0.2.1` — [MIT](https://github.com/GeyserMC/MCProtocolLib/blob/master/LICENSE.txt)
- Cloudburst NBT `3.1.0.Final` — [Apache-2.0](https://github.com/CloudburstMC/NBT/blob/master/LICENSE)
- Cloudburst Math API/Immutable `2.0` — [MIT](https://github.com/CloudburstMC/math/blob/master/LICENSE.txt)
- Cloudburst/NukkitX fastutil modules `8.5.3` — [Apache-2.0](https://github.com/CloudburstMC/fastutil/blob/develop/LICENSE-2.0)

Gson is not bundled or relocated. MCProtocolLib and Adventure share the Gson runtime supplied by
Velocity because Adventure's public serializer API exposes Gson types in method descriptors.

The complete MCProtocolLib MIT text is shipped in the plugin JAR at
`META-INF/licenses/MCProtocolLib-LICENSE.txt`. Maven license metadata for the transitive artifacts
also remains in the shaded JAR.

## ViaVersion Common

- Project: [ViaVersion/ViaVersion](https://github.com/ViaVersion/ViaVersion)
- Artifact: `com.viaversion:viaversion-common:5.12.3`
- Download URL: `https://repo.viaversion.com/com/viaversion/viaversion-common/5.12.3/viaversion-common-5.12.3.jar`
- SHA-256: `baae1443e63fb34b8b64ecd3c74277d5fda8ffd98562c16045237c63b6bdc3ef`
- License: [GNU GPL version 3](https://github.com/ViaVersion/ViaVersion/blob/master/LICENSE)
- Corresponding source: [ViaVersion 5.12.3 tag](https://github.com/ViaVersion/ViaVersion/tree/5.12.3)
- Use in VeloAuth: not included in the VeloAuth JAR. This exact release is the build-pinned fallback.
  Embedded mode may additionally stage only an exact candidate whose URL and SHA-256 are already
  embedded in the installed release. It never follows mutable metadata. External mode does not
  check, download or load any ViaVersion artifact.

The ViaVersion Common artifact contains relocated upstream components, including ViaNBT (MIT), Gson
(Apache-2.0) and SnakeYAML (Apache-2.0). Their Maven license metadata and ViaVersion's complete GPL-3.0
text remain present in the downloaded JAR.

## Reproducibility and updates

`scripts/verify-embedded-dependencies.sh` independently verifies the release fallback hashes in CI.
`scripts/build-latest-protocol.sh` accepts an independently reviewed SHA-256 before pinning a
snapshot to immutable timestamped bytes and running the quality and smoke gates. The running
plugin never hot-swaps code. A staged candidate must pass classloading, translation-path and
loopback login/keepalive validation on restart or VeloAuth falls back to the approved stable runtime.
