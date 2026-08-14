//! Deciding whether a path is inside its allowed roots.
//!
//! # Design decision: resolve first, compare second — never the other way round
//!
//! The classic version of this bug compares the path as a string, then opens
//! it. Both `../../etc/passwd` and a symlink pointing out of the tree defeat
//! that, and the second one defeats it *silently*, because the string looks
//! entirely reasonable. So every path is fully resolved before any comparison
//! happens, and the comparison is on components rather than on a string prefix.
//!
//! # Design decision: component-wise comparison, not `starts_with` on strings
//!
//! `/home/user/project-secrets` has the string prefix `/home/user/project`.
//! Comparing `Path` components instead of text makes that impossible, which is
//! why `contains` walks components rather than calling `str::starts_with`.
//!
//! # Design decision: a path that does not exist yet still has to be resolved
//!
//! A write creates its target, so `canonicalize` fails on exactly the paths a
//! write cares about. Resolving the deepest ancestor that *does* exist and
//! re-attaching the remainder gives a real answer for new files while still
//! following any symlink in the existing part of the chain — which is where an
//! escape would actually be hidden.

use std::path::{Component, Path, PathBuf};

use crate::error::{GritError, Result};

/// Is `candidate` inside `root`? Both must already be resolved.
///
/// Equal paths count as contained: a root is inside itself.
pub fn contains(root: &Path, candidate: &Path) -> bool {
    let mut r = root.components();
    let mut c = candidate.components();
    loop {
        match (r.next(), c.next()) {
            // Root exhausted: everything matched, candidate is at or below it.
            (None, _) => return true,
            // Candidate exhausted first: it is an ancestor, not a descendant.
            (Some(_), None) => return false,
            (Some(a), Some(b)) if a == b => continue,
            _ => return false,
        }
    }
}

/// Resolve a path as far as the filesystem allows, following symlinks in the
/// portion that exists.
///
/// Returns the resolved absolute path. Purely lexical `..` handling is applied
/// only to the non-existent tail, where there is nothing to follow.
pub fn resolve(path: &Path) -> Result<PathBuf> {
    if let Ok(real) = path.canonicalize() {
        return Ok(real);
    }

    // Walk up to the deepest existing ancestor, remembering what we stripped.
    let mut tail: Vec<Component<'_>> = Vec::new();
    let mut cursor = path;
    loop {
        match cursor.parent() {
            Some(parent) => {
                if let Some(name) = cursor.file_name() {
                    tail.push(Component::Normal(name));
                } else if cursor.components().next_back() == Some(Component::ParentDir) {
                    tail.push(Component::ParentDir);
                }
                if let Ok(real_parent) = parent.canonicalize() {
                    let mut out = real_parent;
                    for component in tail.iter().rev() {
                        match component {
                            // `..` in the non-existent tail is resolved
                            // lexically. There is no symlink to follow here,
                            // because none of it exists yet.
                            Component::ParentDir => {
                                // Deliberately not folded into a match guard.
                                // clippy offers `ParentDir if !out.pop()`,
                                // which is equivalent only because the guard
                                // mutates `out` as a side effect. It works, and
                                // it is a trap for whoever reads it next.
                                let popped = out.pop();
                                if !popped {
                                    return Err(GritError::PathEscape {
                                        attempted: path.to_path_buf(),
                                    });
                                }
                            }
                            Component::Normal(name) => out.push(name),
                            _ => {}
                        }
                    }
                    return Ok(out);
                }
                cursor = parent;
            }
            None => {
                // Ran out of ancestors without finding anything real.
                return Err(GritError::PathEscape {
                    attempted: path.to_path_buf(),
                });
            }
        }
    }
}

/// Resolve `candidate` and confirm it sits inside at least one allowed root and
/// outside every denied root.
///
/// Denied roots are checked *after* allowed roots and override them, so
/// `~/project` can be granted while `~/project/.git` stays protected.
pub fn check(candidate: &Path, allowed: &[PathBuf], denied: &[PathBuf]) -> Result<PathBuf> {
    if allowed.is_empty() {
        return Err(GritError::Denied {
            reason: "this tool has no filesystem access".to_string(),
        });
    }

    let resolved = resolve(candidate)?;

    for deny in denied {
        let deny_resolved = resolve(deny).unwrap_or_else(|_| deny.clone());
        if contains(&deny_resolved, &resolved) {
            return Err(GritError::Denied {
                reason: format!("{} is inside a denied root", resolved.display()),
            });
        }
    }

    for allow in allowed {
        let allow_resolved = resolve(allow).unwrap_or_else(|_| allow.clone());
        if contains(&allow_resolved, &resolved) {
            return Ok(resolved);
        }
    }

    Err(GritError::PathEscape {
        attempted: candidate.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn a_path_is_inside_itself() {
        assert!(contains(Path::new("/a/b"), Path::new("/a/b")));
    }

    #[test]
    fn a_child_is_inside_its_parent() {
        assert!(contains(Path::new("/a/b"), Path::new("/a/b/c/d")));
    }

    #[test]
    fn a_parent_is_not_inside_its_child() {
        assert!(!contains(Path::new("/a/b/c"), Path::new("/a/b")));
    }

    #[test]
    fn a_sibling_sharing_a_string_prefix_is_not_contained() {
        // The reason this compares components and not strings.
        assert!(!contains(
            Path::new("/home/user/project"),
            Path::new("/home/user/project-secrets/key.pem")
        ));
    }

    #[test]
    fn dot_dot_traversal_is_caught() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("work");
        fs::create_dir_all(&root).expect("mkdir");
        let outside = root.join("../../etc/passwd");
        let err = check(&outside, std::slice::from_ref(&root), &[]).expect_err("must refuse");
        assert_eq!(err.code(), "path_escape", "{err}");
    }

    #[test]
    fn a_symlink_pointing_out_of_the_tree_is_caught() {
        // The interesting case: the string looks entirely reasonable.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("work");
        let secret_dir = dir.path().join("secrets");
        fs::create_dir_all(&root).expect("mkdir");
        fs::create_dir_all(&secret_dir).expect("mkdir");
        fs::write(secret_dir.join("key.pem"), b"shh").expect("write");

        let link = root.join("innocent.pem");
        #[cfg(unix)]
        std::os::unix::fs::symlink(secret_dir.join("key.pem"), &link).expect("symlink");

        #[cfg(unix)]
        {
            let err = check(&link, std::slice::from_ref(&root), &[]).expect_err("must refuse");
            assert_eq!(err.code(), "path_escape", "{err}");
        }
    }

    #[test]
    fn an_ordinary_path_inside_the_root_is_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let file = root.join("notes.txt");
        fs::write(&file, b"hello").expect("write");
        assert!(check(&file, &[root], &[]).is_ok());
    }

    #[test]
    fn a_file_that_does_not_exist_yet_still_resolves() {
        // Writes create their target, so this is the common case, not an edge.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let new_file = root.join("subdir-to-be/output.txt");
        let resolved =
            check(&new_file, std::slice::from_ref(&root), &[]).expect("should be allowed");
        assert!(contains(&resolve(&root).expect("root resolves"), &resolved));
    }

    #[test]
    fn a_denied_root_overrides_an_allowed_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let git = root.join(".git");
        fs::create_dir_all(&git).expect("mkdir");
        fs::write(git.join("config"), b"[core]").expect("write");

        assert!(check(
            &root.join("src.rs"),
            std::slice::from_ref(&root),
            std::slice::from_ref(&git),
        )
        .is_ok());
        let err = check(&git.join("config"), &[root], &[git]).expect_err("must refuse");
        assert_eq!(err.code(), "denied", "{err}");
    }

    #[test]
    fn no_allowed_roots_means_no_filesystem_access() {
        let err = check(Path::new("/tmp/anything"), &[], &[]).expect_err("must refuse");
        assert_eq!(err.code(), "denied");
    }
}
