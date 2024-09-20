use std::borrow::Cow::{self, Owned};
use std::collections::HashSet;
use std::iter;

use ansi_term::Colour::{Green, Red};
use rustyline::completion::{extract_word, Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::{self, MatchingBracketValidator, Validator};
use rustyline::{CompletionType, Context};
use rustyline_derive::Helper;

#[cfg(unix)]
static DEFAULT_BREAK_CHARS: [char; 18] = [
    ' ', '\t', '\n', '"', '\\', '\'', '`', '@', '$', '>', '<', '=', ';', '|', '&', '{', '(', '\0',
];

#[cfg(unix)]
static ESCAPE_CHAR: Option<char> = Some('\\');
// Remove \ to make file completion works on windows
#[cfg(windows)]
static DEFAULT_BREAK_CHARS: [char; 17] = [
    ' ', '\t', '\n', '"', '\'', '`', '@', '$', '>', '<', '=', ';', '|', '&', '{', '(', '\0',
];
#[cfg(windows)]
static ESCAPE_CHAR: Option<char> = None;

#[derive(Helper)]
pub struct CkbCompleter<'a> {
    clap_app: clap::App<'a>,
    completer: FilenameCompleter,
    validator: MatchingBracketValidator,
}

impl<'a> CkbCompleter<'a> {
    pub fn new(clap_app: clap::App<'a>) -> Self {
        CkbCompleter {
            clap_app,
            completer: FilenameCompleter::new(),
            validator: MatchingBracketValidator::new(),
        }
    }

    pub fn get_completions(app: &clap::App<'a>, args: &[String]) -> Vec<(String, String)> {
        let args_set = args.iter().collect::<HashSet<&String>>();
        let switched_completions =
            |short: Option<char>, long: Option<&str>, multiple: bool, required: bool| {
                let names = vec![
                    short.map(|s| format!("-{}", s)),
                    long.map(|s| format!("--{}", s)),
                ]
                .into_iter()
                .flatten()
                .map(|s| {
                    let display = if required {
                        format!("{}(*)", s)
                    } else {
                        s.clone()
                    };
                    (display, s)
                })
                .collect::<Vec<(String, String)>>();

                if !multiple && names.iter().any(|(_, s)| args_set.contains(&s)) {
                    vec![]
                } else {
                    names
                }
            };
        app.get_subcommands()
            .iter()
            .map(|app| {
                [
                    vec![(app.get_name().to_owned(), app.get_name().to_owned())],
                    app.get_all_aliases()
                        .map(|alias| (alias.to_owned(), alias.to_owned()))
                        .collect::<Vec<_>>(),
                ]
                .concat()
            })
            .chain(app.get_arguments().iter().map(|a| {
                switched_completions(
                    a.get_short(),
                    a.get_long(),
                    a.is_set(clap::ArgSettings::MultipleValues),
                    a.is_set(clap::ArgSettings::Required),
                )
            }))
            .collect::<Vec<Vec<(String, String)>>>()
            .concat()
    }

    pub fn find_subcommand<'s, Iter: iter::Iterator<Item = &'s str>>(
        app: clap::App<'a>,
        mut prefix_names: iter::Peekable<Iter>,
    ) -> Option<clap::App<'a>> {
        if let Some(name) = prefix_names.next() {
            for inner_app in app.get_subcommands().iter() {
                if inner_app.get_name() == name
                    || inner_app.get_all_aliases().any(|alias| alias == name)
                {
                    return if prefix_names.peek().is_none() {
                        Some(inner_app.to_owned())
                    } else {
                        Self::find_subcommand(inner_app.to_owned(), prefix_names)
                    };
                }
            }
        }
        if prefix_names.peek().is_none() || app.get_subcommands().is_empty() {
            Some(app)
        } else {
            None
        }
    }
}

impl<'a> Completer for CkbCompleter<'a> {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let (start, word) = extract_word(line, pos, ESCAPE_CHAR, |char| {
            DEFAULT_BREAK_CHARS.contains(&char)
        });
        let args = shell_words::split(&line[..pos]).unwrap();
        let word_lower = word.to_lowercase();
        let tmp_pair = Self::find_subcommand(
            self.clap_app.to_owned(),
            args.iter().map(String::as_str).peekable(),
        )
        .map(|current_app| Self::get_completions(&current_app, &args))
        .unwrap_or_default();

        let (start, pairs) = if word_lower.is_empty() {
            let pairs = tmp_pair
                .into_iter()
                .map(|(display, replacement)| Pair {
                    display,
                    replacement,
                })
                .collect::<Vec<_>>();
            (start, pairs)
        } else {
            let pairs = tmp_pair
                .clone()
                .into_iter()
                .filter(|(_, replacement)| string_include(&replacement.to_lowercase(), &word_lower))
                .map(|(display, replacement)| Pair {
                    display,
                    replacement,
                })
                .collect::<Vec<_>>();

            if pairs
                .iter()
                .any(|ref mut x| x.replacement.to_lowercase().contains(&word_lower))
            {
                let pairs = tmp_pair
                    .into_iter()
                    .filter(|(_, replacement)| replacement.to_lowercase().contains(&word_lower))
                    .map(|(display, replacement)| Pair {
                        display,
                        replacement,
                    })
                    .collect::<Vec<_>>();
                (start, pairs)
            } else {
                let pairs = tmp_pair
                    .into_iter()
                    .filter(|(_, replacement)| {
                        string_include(&replacement.to_lowercase(), &word_lower)
                    })
                    .map(|(display, replacement)| Pair {
                        display,
                        replacement,
                    })
                    .collect::<Vec<_>>();
                (start, pairs)
            }
        };
        if pairs.is_empty() {
            self.completer.complete(line, pos, ctx)
        } else {
            Ok((start, pairs))
        }
    }
}

impl<'a> Hinter for CkbCompleter<'a> {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl<'a> Validator for CkbCompleter<'a> {
    fn validate(
        &self,
        ctx: &mut validate::ValidationContext,
    ) -> rustyline::Result<validate::ValidationResult> {
        self.validator.validate(ctx)
    }

    fn validate_while_typing(&self) -> bool {
        self.validator.validate_while_typing()
    }
}

impl<'a> Highlighter for CkbCompleter<'a> {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight_candidate<'c>(
        &self,
        candidate: &'c str,
        _completion: CompletionType,
    ) -> Cow<'c, str> {
        let candidate_with_color = candidate
            .split('\n')
            .map(|param| {
                if param.contains('*') {
                    Red.paint(param).to_string()
                } else if !param.starts_with("--") {
                    Green.paint(param).to_string()
                } else {
                    param.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        Owned(candidate_with_color)
    }
}

pub fn string_include(x: &str, y: &str) -> bool {
    let len_pat = y.len();
    let p: Vec<char> = x.chars().collect();
    let q: Vec<char> = y.chars().collect();

    let mut sum = 0;

    for item in p {
        if item == q[sum] {
            sum += 1;
            if sum == len_pat {
                return true;
            }
        }
    }
    false
}
