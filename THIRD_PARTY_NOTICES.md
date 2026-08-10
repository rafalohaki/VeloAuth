# Third-party notices

VeloAuth is distributed under the license in [LICENSE](LICENSE). Its embedded-limbo feature also
uses the following independently maintained software. This notice is informational and does not
replace the license text supplied by each upstream project.

## MCProtocolLib

- Project: [GeyserMC/MCProtocolLib](https://github.com/GeyserMC/MCProtocolLib)
- Artifact: `org.geysermc.mcprotocollib:protocol:26.2-20260809.160751-16`
- SHA-256: `07ec18ba92c8b4041286eeff2470e08257fd1f383881515cba4a0a9bf6fa98c1`
- License: [MIT](https://github.com/GeyserMC/MCProtocolLib/blob/master/LICENSE.txt)
- Use in VeloAuth: shaded and package-relocated network engine for the loopback-only embedded
  listener. Netty is not bundled or relocated; Velocity supplies the shared Netty runtime.

MCProtocolLib brings the following package-relocated runtime dependencies into the VeloAuth JAR:

- Cloudburst NBT `3.0.4.Final` — [Apache-2.0](https://github.com/CloudburstMC/NBT/blob/master/LICENSE)
- Cloudburst Math API/Immutable `2.0` — [MIT](https://github.com/CloudburstMC/math/blob/master/LICENSE.txt)
- Cloudburst/NukkitX fastutil modules `8.5.3` — [Apache-2.0](https://github.com/CloudburstMC/fastutil/blob/develop/LICENSE-2.0)

Gson is not bundled or relocated. MCProtocolLib and Adventure share the Gson runtime supplied by
Velocity because Adventure's public serializer API exposes Gson types in method descriptors.

The complete MCProtocolLib MIT text is shipped in the plugin JAR at
`META-INF/licenses/MCProtocolLib-LICENSE.txt`. Maven license metadata for the transitive artifacts
also remains in the shaded JAR.

## ViaVersion Common

- Project: [ViaVersion/ViaVersion](https://github.com/ViaVersion/ViaVersion)
- Artifact: `com.viaversion:viaversion-common:5.11.0`
- Download URL: `https://repo.viaversion.com/com/viaversion/viaversion-common/5.11.0/viaversion-common-5.11.0.jar`
- SHA-256: `a4dd9f63257ed923f73a64ecece31010acd04247db12855383172e1226912b3e`
- License: [GNU GPL version 3](https://github.com/ViaVersion/ViaVersion/blob/master/LICENSE)
- Corresponding source: [ViaVersion 5.11.0 tag](https://github.com/ViaVersion/ViaVersion/tree/5.11.0)
- Use in VeloAuth: not included in the VeloAuth JAR. This exact release is the build-pinned fallback.
  Embedded mode may additionally stage an exact timestamped artifact from ViaVersion's official
  latest snapshot metadata, verify its published SHA-256, and load it on the next restart in a
  dedicated classloader. External mode does not check, download or load any ViaVersion artifact.

The ViaVersion Common artifact contains relocated upstream components, including ViaNBT (MIT), Gson
(Apache-2.0) and SnakeYAML (Apache-2.0). Their Maven license metadata and ViaVersion's complete GPL-3.0
text remain present in the downloaded JAR.

## Reproducibility and updates

`scripts/verify-embedded-dependencies.sh` independently verifies the release fallback hashes in CI.
`scripts/build-latest-protocol.sh` can resolve the current snapshot to immutable timestamped bytes,
record their provenance and run the full quality/smoke gates. At runtime, only embedded mode checks
the official snapshot metadata after startup; it never hot-swaps code. A staged artifact must pass
classloading and complete-path validation on restart or VeloAuth automatically returns to the last
working/pinned runtime. Exact ViaVersion snapshot source is available from the upstream
[ViaVersion repository](https://github.com/ViaVersion/ViaVersion).
