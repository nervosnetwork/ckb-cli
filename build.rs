use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use git2::Repository;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("build_info.rs");
    let mut f = File::create(&dest_path).unwrap();

    let commit_id = match Repository::discover(".") {
        Ok(repo) => repo
            .revparse("HEAD")
            .map(|rev_spec| rev_spec.from().map(|obj| obj.id().to_string()))
            .unwrap()
            .unwrap(),
        Err(_) => ("unknown".to_string()),
    };

    let code = format!(
        "
    pub fn get_commit_id() -> &'static str {{
           {:?}
    }}
   ",
        commit_id
    );

    f.write_all(code.as_bytes()).unwrap();
}
