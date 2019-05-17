use std::env;
use std::io;
use std::rc::Rc;

use ansi_term::Colour::Red;
use atty;

use crate::utils::json_color::Colorizer;

pub fn is_a_tty(stderr: bool) -> bool {
    let stream = if stderr {
        atty::Stream::Stderr
    } else {
        atty::Stream::Stdout
    };
    atty::is(stream)
}

pub fn is_term_dumb() -> bool {
    env::var("TERM").ok() == Some(String::from("dumb"))
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Raw,
    Json,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ColorWhen {
    Auto,
    #[allow(dead_code)]
    Always,
    Never,
}

impl Default for ColorWhen {
    fn default() -> Self {
        let is_a_tty = is_a_tty(false);
        let is_term_dumb = is_term_dumb();
        if is_a_tty && !is_term_dumb {
            ColorWhen::Auto
        } else {
            ColorWhen::Never
        }
    }
}

pub struct Printer {
    format: OutputFormat,
    color: ColorWhen,
}

impl Default for Printer {
    fn default() -> Self {
        Printer {
            format: OutputFormat::Json,
            color: ColorWhen::default(),
        }
    }
}

impl Printer {
    // pub fn color(&self) -> bool {
    //     self.color != ColorWhen::Never
    // }

    pub fn switch_format(&mut self) {
        match self.format {
            OutputFormat::Raw => {
                self.format = OutputFormat::Json;
            }
            OutputFormat::Json => {
                self.format = OutputFormat::Raw;
            }
        }
    }

    #[allow(dead_code)]
    pub fn set_color(&mut self, color: ColorWhen) -> &mut Self {
        self.color = color;
        self
    }

    pub fn print<W: io::Write, P: Printable>(
        &self,
        target: &mut W,
        content: &P,
        newline: bool,
        color: Option<ColorWhen>,
    ) -> io::Result<()> {
        let color = match color.unwrap_or(self.color) {
            ColorWhen::Always | ColorWhen::Auto => true,
            ColorWhen::Never => false,
        };
        target.write_all(content.rc_string(self.format, color).as_bytes())?;
        if newline {
            target.write_all(&[b'\n'])?;
        }
        Ok(())
    }

    pub fn println<P: Printable>(&self, content: &P, color: bool) {
        let stdout = io::stdout();
        let color = if color { None } else { Some(ColorWhen::Never) };
        self.print(&mut stdout.lock(), content, true, color)
            .unwrap();
    }

    pub fn eprintln<P: Printable>(&self, content: &P, color: bool) {
        let stderr = io::stderr();
        if color {
            let prefix = Rc::new(format!("{} ", Red.paint(">>")));
            self.print(&mut stderr.lock(), &prefix, false, None)
                .unwrap();
        };
        let color = if color { None } else { Some(ColorWhen::Never) };
        self.print(&mut stderr.lock(), content, true, color)
            .unwrap();
    }
}

pub trait Printable {
    fn rc_string(&self, format: OutputFormat, color: bool) -> Rc<String>;
}

impl Printable for Box<dyn Printable> {
    fn rc_string(&self, format: OutputFormat, color: bool) -> Rc<String> {
        let value = self.as_ref().rc_string(format, color);
        if color {
            Rc::new(Colorizer::arbitrary().colorize_json_str(&value).unwrap())
        } else {
            value
        }
    }
}

impl Printable for String {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(self.clone())
    }
}

impl Printable for Rc<String> {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        self.clone()
    }
}

impl Printable for serde_json::Value {
    fn rc_string(&self, format: OutputFormat, color: bool) -> Rc<String> {
        if let (OutputFormat::Raw, serde_json::Value::String(content)) = (format, self) {
            return Rc::new(content.clone());
        }
        let content = if color {
            Colorizer::arbitrary().colorize_json_value(self).unwrap()
        } else {
            serde_json::to_string_pretty(self).unwrap()
        };
        Rc::new(content)
    }
}

// impl Printable for JsonRpcResponse {
//     fn rc_string(&self, _format: OutputFormat, color: bool) -> Rc<String> {
//         let content = format!("{:?}", self);
//         let content = if color {
//             Colorizer::arbitrary()
//                 .colorize_json_str(content.as_str())
//                 .unwrap()
//         } else {
//             content
//         };
//         Rc::new(content)
//     }
// }

// impl Printable for KeyPair {
//     fn rc_string(&self, format: OutputFormat, color: bool) -> Rc<String> {
//         match format {
//             OutputFormat::Json => json!({
//                 "private": format!("0x{}", self.privkey()),
//                 "public": format!("0x{}", self.pubkey()),
//                 "address": format!("0x{:x}", self.address())
//             })
//             .rc_string(format, color),
//             OutputFormat::Raw => {
//                 let content = if color {
//                     format!(
//                         concat!("{} 0x{}\n", "{} 0x{}\n", "{} 0x{:x}"),
//                         Yellow.paint("[ private ]:"),
//                         self.privkey(),
//                         Yellow.paint("[ public  ]:"),
//                         self.pubkey(),
//                         Yellow.paint("[ address ]:"),
//                         self.address()
//                     )
//                 } else {
//                     format!(
//                         concat!("{} 0x{}\n", "{} 0x{}\n", "{} 0x{:x}"),
//                         "[ private ]:",
//                         self.privkey(),
//                         "[ public  ]:",
//                         self.pubkey(),
//                         "[ address ]:",
//                         self.address()
//                     )
//                 };
//                 Rc::new(content)
//             }
//         }
//     }
// }
