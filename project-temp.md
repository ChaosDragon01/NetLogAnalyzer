


log-analyzer/
│
├── engine/                     RUST 
│   ├── Cargo.toml              # Rust dependencies (pnet, serde)
│   └── src/
│       ├── main.rs             # Entry point (CLI args, thread management)
│       ├── sniffer.rs          # (replaces parser.py) Raw socket/pcap logic
│       ├── rules.rs            # (replaces filters.py) Fast logic (IP blocking)
│       └── events.rs           # JSON Structs for output
│
├── dashboard/                  TYPESCRIPT 
│   ├── package.json            # Node dependencies (express, socket.io)
│   ├── tsconfig.json
│   └── src/
│       ├── main.ts             # Entry point (Spawns the Rust engine)
│       ├── processor.ts        # Reads Rust's JSON stdout stream
│       ├── server/             # (replaces api/server.py)
│       │   ├── app.ts          # Express/Fastify app
│       │   └── socket.ts       # Websocket for live frontend updates
│       └── services/           # (replaces alerts/)
│           ├── discord.ts      # (replaces discord_alert.py)
│           └── database.ts     # (replaces storage/database.py)
│
├── config/                     SHARED CONFIG
│   ├── rules.yaml              # Detection rules (Rust reads this)
│   └── alert_config.json       # Webhook URLs (TypeScript reads this)
│
├── logs/                       SHARED DATA
│   └── dumps/                  # Where Rust dumps raw .pcap files 
│
├── docker-compose.yml          # Orchestrates running both together
└── README.md