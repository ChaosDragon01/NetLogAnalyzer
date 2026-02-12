# 1. Create the root
mkdir log-analyzer-hybrid
cd log-analyzer-hybrid

# 2. Initialize the Rust Engine
cargo new engine

# 3. Initialize the TypeScript Dashboard
mkdir dashboard
cd dashboard
npm init -y
npm install typescript ts-node @types/node express socket.io
npx tsc --init
cd ..

# 4. Create the shared folders
mkdir config logs
touch config/rules.yaml
touch docker-compose.yml