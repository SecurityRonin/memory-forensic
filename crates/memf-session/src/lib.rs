//! Memory-dump analysis bootstrap (RED placeholder — implementation arrives in
//! the GREEN commit). The OS-detection / CR3 / list-head bootstrap is extracted
//! here from the `memory-forensic` binary so consumers (e.g. 4n6mount) can drive
//! the analysis from a library instead of the CLI.
