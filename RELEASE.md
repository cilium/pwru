# RELEASE

Release process and checklist for `pwru`.

This repository doesn't use release branches. All releases currently stem from
the master branch.

## Prepare the variables

These variables will be used in the commands throughout the document to allow
copy-pasting.

### Version

If releasing a new version v0.0.3 with the latest release being v0.0.2, for
example, they will look as follows:

    export RELEASE=v0.0.3
    export LAST_RELEASE=v0.0.2

### Commit SHA to release

    export COMMIT_SHA=<commit-sha-to-release>

## Tag a release

    git tag -a $RELEASE -m "$RELEASE release" $COMMIT_SHA && git push origin $RELEASE

## Update the GitHub release notes

When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
draft release, building artifacts and attaching them to the draft release. Once
the draft is ready, use the "Auto-generate release notes" button to generate
the release notes from PR titles, review them and publish the release.
