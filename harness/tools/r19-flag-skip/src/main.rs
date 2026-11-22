//! Prints the instance name creance derives for (profile, environment_dir),
//! so run.sh can lay out QEMU-backend fixtures where cmd_escape_test looks.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (profile, ws) = (&args[1], &args[2]);
    println!("{}", creance_vm::vm::instance_name(profile, ws));
}
