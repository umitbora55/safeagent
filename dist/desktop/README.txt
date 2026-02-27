SafeAgent release output:
- dist/desktop/<os>/ contains desktop binary and companion services.
- Signing placeholders:
  - macOS: run `codesign --force --options runtime --sign ...` in packaging pipeline.
  - Windows: run `signtool sign` in packaging pipeline.
  - Linux: packaging can use .deb/.AppImage with distribution signing at repo level.
