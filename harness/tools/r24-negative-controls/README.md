# r24-negative-controls
Mutation matrix for the F-086/F-087 fix surfaces (v0.6.15): cp backup → perl inject → grep -c → `cargo test --locked` → restore → md5sum -c.
`sh run.sh` (all) or `ONLY="NC-X NC-Y" sh run.sh`. Evidence: `evidence.log`, `evidence-rerun.log`, `logs/`. Greens → F-091.
