import { spawn } from 'child_process';
import path from 'path';

console.log("🚀 Dashboard starting...");

// Point to where Rust builds its binary
const enginePath = path.resolve(__dirname, '../../engine/target/debug/engine');
console.log(`Looking for engine at: ${enginePath}`);

// Placeholder for spawning logic
// const rustProcess = spawn(enginePath);
