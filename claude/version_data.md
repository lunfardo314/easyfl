# Goal 1 (DONE)

Add additional field `VersionData []byte` to the `Library` structure.
   - field value can be empty (`nil`)
   - the field is represented as a top-level key `version_data:` in the .yaml form of the library
   - in yaml, value of the `version_data:` is string
   - absence of the `version_data:` means empty value
   - upon library upgrade, `version_data` field is updated only if the new value exists and is non-empty (after trimming leading/trailing whitespace)
   - `VersionData` must be included in the library hash calculation

# Goal 2 (DONE)

In EasyFL library, type of the entry (embedded or extended/formula) is defined by the function code.
It means embedded function cannot be upgraded with extended and vice versa.

Enforce necessary checking of it upon upgrading the library

# Goal 3 (DONE)

Fix YAML escaping in `ToYAML` function. When `version_data` contains JSON or other strings with
special characters (quotes, backslashes, newlines), the generated YAML was invalid.

**Problem**: `ToYAML` was generating:
```yaml
version_data: "{"txValidation":"txLayoutValidator"}"
```
This is invalid YAML because the inner quotes are not escaped.

**Solution**: Added `yamlEscapeString()` helper function in `serde_tools.go` that properly escapes:
- Double quotes (`"` → `\"`)
- Backslashes (`\` → `\\`)
- Newlines, carriage returns, tabs

Applied escaping to all string fields in YAML output:
- `version_data`
- `sym`
- `description`
- `embedded_as`

**Tests added**:
- `TestVersionDataEscaping` - verifies JSON in version_data round-trips correctly
- `TestYamlEscapeString` - unit tests for the escape function