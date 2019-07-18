fn main() {
    // forward git repo hashes we build at
    println!(
        "cargo:rustc-env=COMMIT_DESCRIBE={}",
        ckb_build_info::get_commit_describe().unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=COMMIT_DATE={}",
        ckb_build_info::get_commit_date().unwrap_or_default()
    );
}
