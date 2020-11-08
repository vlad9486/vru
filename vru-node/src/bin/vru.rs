use std::env;
use structopt::StructOpt;
use tokio::{io::AsyncWriteExt, net::UnixStream};

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, short, default_value = "main")]
    name: String,
    #[structopt(short)]
    command: String,
}

#[tokio::main]
async fn main() {
    let opts = Opts::from_args();
    let control_path = format!("{}/.vru/{}.sock", env::var("HOME").unwrap(), opts.name);

    let mut control = UnixStream::connect(control_path).await.unwrap();
    control.write_all(opts.command.as_bytes()).await.unwrap();
}
