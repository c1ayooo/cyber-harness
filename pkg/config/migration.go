package config

// migrateDocument runs the composition's DocumentMigration hook over the file
// and CLI values before they are resolved (4zdesign/19 已决 19: the fence
// section's judge keys used to live in the guardrail section, and the legacy
// spelling must keep reading).
//
// The hook sees one document: the file's sections, with a CLI section added
// where the file has none. The migrated document is written back into the
// file values, which every later stage reads — a section the hook moved to a
// new key therefore resolves from the file, and a CLI section that took part
// in the migration is written there as well as staying on the CLI, where it
// still overrides.
func migrateDocument(migrate func(document map[string]any), file, cli Values) {
	document := map[string]any{}
	for key, section := range file {
		if section != nil {
			document[key] = section
		}
	}
	for key, section := range cli {
		if section != nil {
			if _, exists := document[key]; !exists || document[key] == nil {
				document[key] = section
			}
		}
	}
	migrate(document)
	for key := range file {
		delete(file, key)
	}
	for key, value := range document {
		if section, ok := value.(map[string]any); ok {
			file[key] = section
		}
	}
}
