// SPDX-License-Identifier: BSD-3-Clause
//! Small pure helpers, kept out of `sys` so they can be tested on the host.

use alloc::vec::Vec;

/// The trailing component of a path.
///
/// Unlike the C loader's `basename_internal`, this does not modify its input:
/// that function overwrote trailing slashes with NULs in a string the caller
/// still owned, which is fine for a `strdup`'d copy and quietly corrupting for
/// anything else.
pub fn basename(path: &[u8]) -> &[u8] {
    let end = path
        .iter()
        .rposition(|&c| c != b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    let stripped = &path[..end];
    match stripped.iter().rposition(|&c| c == b'/') {
        Some(i) => &stripped[i + 1..],
        None => stripped,
    }
}

/// Whether `name` is something to look up in `$PATH`, as opposed to a path in
/// its own right.
pub fn is_bare_name(name: &[u8]) -> bool {
    !name.is_empty() && name[0] != b'/' && name[0] != b'.' && !name.contains(&b'/')
}

/// Candidate paths for `name` across a colon-separated search path, in order.
///
/// An empty element means the current directory, matching the shell and
/// `execvp(3)`; the C version skipped it and produced a path starting with
/// `/`, i.e. silently searched the root.
pub fn path_candidates<'a>(
    name: &'a [u8],
    path_env: &'a [u8],
) -> impl Iterator<Item = Vec<u8>> + 'a {
    path_env.split(|&c| c == b':').filter_map(move |dir| {
        let mut cand: Vec<u8> = Vec::new();
        cand.try_reserve(dir.len() + 1 + name.len()).ok()?;
        if dir.is_empty() {
            cand.extend_from_slice(b".");
        } else {
            cand.extend_from_slice(dir);
        }
        if cand.last() != Some(&b'/') {
            cand.push(b'/');
        }
        cand.extend_from_slice(name);
        Some(cand)
    })
}

/// Print a byte string as text in a log message, without assuming UTF-8.
pub struct Show<'a>(pub &'a [u8]);

impl core::fmt::Display for Show<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &b in self.0 {
            let c = if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '?'
            };
            core::fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn basename_handles_the_awkward_cases() {
        assert_eq!(basename(b"/usr/bin/node"), b"node");
        assert_eq!(basename(b"node"), b"node");
        assert_eq!(basename(b"/usr/bin/"), b"bin");
        assert_eq!(basename(b"/usr/bin///"), b"bin");
        assert_eq!(basename(b"/"), b"");
        assert_eq!(basename(b"///"), b"");
        assert_eq!(basename(b""), b"");
        assert_eq!(basename(b"./x"), b"x");
    }

    #[test]
    fn basename_does_not_modify_its_input() {
        let p = b"/usr/bin/".to_vec();
        let before = p.clone();
        let _ = basename(&p);
        assert_eq!(p, before);
    }

    #[test]
    fn only_bare_names_are_searched() {
        assert!(is_bare_name(b"node"));
        assert!(!is_bare_name(b"/usr/bin/node"));
        assert!(!is_bare_name(b"./node"));
        assert!(!is_bare_name(b"../node"));
        assert!(!is_bare_name(b"bin/node"));
        assert!(!is_bare_name(b""));
    }

    #[test]
    fn candidates_cover_each_element_in_order() {
        let got: Vec<Vec<u8>> = path_candidates(b"node", b"/usr/local/bin:/usr/bin:/bin").collect();
        assert_eq!(
            got,
            vec![
                b"/usr/local/bin/node".to_vec(),
                b"/usr/bin/node".to_vec(),
                b"/bin/node".to_vec()
            ]
        );
    }

    #[test]
    fn trailing_slashes_do_not_double_up() {
        let got: Vec<Vec<u8>> = path_candidates(b"node", b"/usr/bin/").collect();
        assert_eq!(got, vec![b"/usr/bin/node".to_vec()]);
    }

    #[test]
    fn an_empty_element_means_the_current_directory() {
        let got: Vec<Vec<u8>> = path_candidates(b"node", b"/bin::/usr/bin").collect();
        assert_eq!(
            got,
            vec![
                b"/bin/node".to_vec(),
                b"./node".to_vec(),
                b"/usr/bin/node".to_vec()
            ]
        );
    }

    #[test]
    fn show_escapes_non_printable_bytes() {
        assert_eq!(alloc::format!("{}", Show(b"/usr/bin\x01\xff")), "/usr/bin??");
    }
}
