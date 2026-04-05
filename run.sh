#!/bin/bash

echo "Starting NetLogAnalyzer..."

cleanup() {
    echo "Stopping services..."
    pkill -P $$
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "Starting Rust backend..."
cargo run &

echo "Starting React frontend..."
cd frontend || exit
npm install
npm run dev &

wait