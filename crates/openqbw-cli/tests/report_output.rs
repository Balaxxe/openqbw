// The CLI will wire this module when report commands are added.  Include it
// here so its self-contained unit tests compile without changing main.rs.
#[path = "../src/report_output.rs"]
mod report_output;
