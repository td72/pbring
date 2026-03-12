use assert_cmd::Command;
use predicates::prelude::*;

fn pbring_cmd() -> Command {
    Command::cargo_bin("pbring").unwrap()
}

#[test]
fn cli_list_help() {
    pbring_cmd()
        .arg("list")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--limit"))
        .stdout(predicate::str::contains("--type"));
}

#[test]
fn cli_get_help() {
    pbring_cmd()
        .arg("get")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Get and output"));
}

#[test]
fn cli_no_subcommand() {
    pbring_cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn cli_invalid_subcommand() {
    pbring_cmd().arg("nonexistent").assert().failure();
}

#[test]
fn cli_get_no_stdin() {
    // get with empty stdin should fail
    pbring_cmd()
        .arg("get")
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn cli_get_invalid_id() {
    pbring_cmd()
        .arg("get")
        .write_stdin("not_a_number\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid ID"));
}

#[test]
fn cli_delete_invalid_id() {
    pbring_cmd()
        .arg("delete")
        .write_stdin("abc\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid ID"));
}

#[test]
fn cli_list_invalid_type_filter() {
    // Unknown type filter should return empty (not error)
    pbring_cmd()
        .arg("list")
        .args(["--type", "unknown"])
        .assert()
        .success();
}
