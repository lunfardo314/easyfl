# Goal 1

Add additional field `VersionData []byte` to the `Library` structure.
   - field value can be empty (`nil`)
   - the field is represented as a top-level key `version_data:` in the .yaml form of the library
   - in yaml, value of the `version_data:` is string
   - absence of the `version_data:` means empty value
   - upon library upgrade, `version_data` field is updated only if the new value exists and is non-empty (after trimming leading/trailing whitespace)
   - `VersionData` must be included in the library hash calculation   

# Goal 2

In EasyFL library, type of the entry (embedded or extended/formula) is defined by the function code.
It means embedded function cannot be upgraded with extended and vice versa.

Enforce necessary checking of it upon upgrading the library  