This fixture is a self-contained dataset for checking Anytype export behavior.

Files:
- `config_demo.yaml`: points `logy` at the demo SQLite database.
- `demo.db`: generated from `seed.sql`
- `transcripts/nmap-demo.typescript`: sample `holdmy exec --record-output` transcript linked to a command run

Useful commands:

```bash
go run . domain show --config examples/anytype-export-demo/config_demo.yaml -d demo.example
go run . portscan show --config examples/anytype-export-demo/config_demo.yaml -d demo.example --format text
go run . probe show --config examples/anytype-export-demo/config_demo.yaml -d demo.example
go run . holdmy show --config examples/anytype-export-demo/config_demo.yaml -d demo.example
go run . export anytype --config examples/anytype-export-demo/config_demo.yaml -d demo.example --engagement "Logy Export Demo"
```