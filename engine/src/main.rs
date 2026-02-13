use std::{thread, time::Duration};

fn main() {
    // Mimic the JSON stream for the dashboard
    println!("{\"status\": \"engine_started\", \"message\": \"Rust Engine Online\"}");
    
    loop {
        thread::sleep(Duration::from_secs(5));
        // Placeholder: In the future, this prints packet data
    }
}
