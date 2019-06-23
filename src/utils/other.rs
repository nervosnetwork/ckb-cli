use rpassword::prompt_password_stdout;

pub fn read_password(repeat: bool) -> Result<String, String> {
    let pass = prompt_password_stdout("Password: ").map_err(|err| err.to_string())?;
    if repeat {
        let repeat_pass =
            prompt_password_stdout("Repeat password: ").map_err(|err| err.to_string())?;
        if pass != repeat_pass {
            return Err("Passwords do not match".to_owned());
        }
    }
    Ok(pass)
}
