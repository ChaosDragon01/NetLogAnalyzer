import { spawn } from 'child_process';
import path from 'path';

console.log("Dashboard starting...");

const enginePath = path.resolve(__dirname, '../../engine/target/debug/engine');
console.log(`Looking for engine at: ${enginePath}`);

// Logic to spawn Rust process goes here
