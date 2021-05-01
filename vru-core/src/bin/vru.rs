#![cfg(unix)]

use std::{env, io::Write as _, os::unix::net::UnixStream};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, short, default_value = "main")]
    name: String,
    #[structopt(short)]
    command: String,
}

fn main() {
    let Opts { name, command } = StructOpt::from_args();

    let prefix = env::var("HOME").unwrap_or("/run".to_string());
    let control_path = format!("{}/.vru/{}.sock", prefix, name);

    UnixStream::connect(&control_path)
        .expect(&format!("cannot connect at {}", control_path))
        .write_fmt(format_args!("{}", command))
        .expect(&format!("cannot write command \'{}\'", command));
}
