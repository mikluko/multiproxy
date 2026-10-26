# How to cut a release

This guide shows maintainers how to release a version. `CHANGELOG.md` decides releases: nothing else tags one.

1. Branch from `main`, for example `release/v<version>`, where `<version>` is the version to release, such as
   `0.5.0`.
1. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [<version>] - <date>`, where `<date>` is today in
   `YYYY-MM-DD` form, and open a fresh, empty `## [Unreleased]` above it.
1. At the foot of `CHANGELOG.md`, point `[Unreleased]` at `v<version>...HEAD` and add a `[<version>]` link
   comparing the previous tag with `v<version>`.
1. Open a pull request into `main` and merge it once CI passes.

On the push to `main`, the Release workflow tags `v<version>` and publishes a Forgejo release with the changelog
entry as its notes.
