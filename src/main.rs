use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::process;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

const MAX_PORT: u16 = 65535;
const DEFAULT_THREADS: u16 = 4;
const DEFAULT_PORT_START: u16 = 1;
const DEFAULT_PORT_END: u16 = MAX_PORT;

struct Arguments {
    ipaddr: IpAddr,
    threads: u16,
    start_port: u16,
    end_port: u16,
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments");
        } else if args.len() > 5 {
            return Err("too many arguments");
        }

        let flag = &args[1];

        if flag.contains("-h") || flag.contains("-help") {
            if args.len() == 2 {
                println!(
                    "Usage: ip_sniffer <IP_ADDRESS> [-j THREADS] [-p START_PORT END_PORT]
                \n\r       -h or -help to show this help message"
                );
                return Err("help");
            } else {
                return Err("too many arguments");
            }
        }

        let ipaddr = match IpAddr::from_str(flag) {
            Ok(ip) => ip,
            Err(_) => return Err("invalid IP address"),
        };

        let mut threads = DEFAULT_THREADS;
        let mut start_port = DEFAULT_PORT_START;
        let mut end_port = DEFAULT_PORT_END;

        if args.len() > 2 {
            if args[2].contains("-j") {
                if let Some(t) = args.get(3) {
                    threads = match t.parse::<u16>() {
                        Ok(t) if t > 0 => t,
                        _ => return Err("failed to parse thread number"),
                    };
                } else {
                    return Err("missing thread number argument");
                }
            } else if args[2].contains("-p") {
                if let Some(start) = args.get(3) {
                    if let Ok(s) = start.parse::<u16>() {
                        start_port = s;
                    } else {
                        return Err("failed to parse start port number");
                    }
                } else {
                    return Err("missing start port number argument");
                }
                if let Some(end) = args.get(4) {
                    if let Ok(e) = end.parse::<u16>() {
                        end_port = e;
                    } else {
                        return Err("failed to parse end port number");
                    }
                } else {
                    return Err("missing end port number argument");
                }
            }
        }

        if start_port > end_port || end_port > MAX_PORT {
            return Err("port range out of bounds");
        }

        Ok(Arguments {
            ipaddr,
            threads,
            start_port,
            end_port,
        })
    }
}

fn scan(tx: Sender<u16>, start_port: u16, end_port: u16, addr: IpAddr, num_threads: u16, thread_id: u16) {
    let mut port = start_port + thread_id;
    let delay = Duration::from_millis(50); // Rate limit to avoid overwhelming the target

    while port <= end_port {
        match TcpStream::connect_timeout(&(addr, port).into(), Duration::from_secs(1)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        port += num_threads;
        thread::sleep(delay);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let arguments = Arguments::new(&args).unwrap_or_else(|err| {
        if err.contains("help") {
            process::exit(0);
        } else {
            eprintln!("{} problem parsing arguments: {}", program, err);
            process::exit(1);
        }
    });

    let num_threads = arguments.threads;
    let addr = arguments.ipaddr;
    let start_port = arguments.start_port;
    let end_port = arguments.end_port;
    
    let (tx, rx) = channel();
    
    for i in 0..num_threads {
        let tx = tx.clone();
        let addr = addr.clone();
        thread::spawn(move || {
            scan(tx, start_port, end_port, addr, num_threads, i);
        });
    }

    let mut out = vec![];
    drop(tx);

    for p in rx {
        out.push(p);
    }

    println!("\nScan complete.");
    out.sort();
    for v in out {
        println!("Port {} is open", v);
    }
}
