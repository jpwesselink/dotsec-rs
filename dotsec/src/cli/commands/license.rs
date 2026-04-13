use clap::Command;
use std::time::Duration;

use crate::default_options::DefaultOptions;

const LICENSE_TEXT: &str = "\
MIT License

Copyright (c) 2025 JP Wesselink

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.";

pub fn command() -> Command {
    Command::new("license")
        .about("Show the dotsec license")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    _default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("license").is_none() {
        return Ok(());
    }

    use chromakopia::animate;

    animate::Sequence::new(LICENSE_TEXT)
        .rainbow(Duration::from_secs(4))
        .fade_to_foreground(Duration::from_millis(600))
        .run(1.0)
        .await;

    println!();

    Ok(())
}
