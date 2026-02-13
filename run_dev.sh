#!/bin/bash
# Builds Rust and starts Node
echo "Building Rust Engine..."
cd engine && cargo build && cd ..

echo "Starting Dashboard..."
cd dashboard && npm run dev
