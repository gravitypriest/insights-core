#!/bin/bash
PYTHON=${1:-python}
CLIENT_REFS=("nightly" "beta" "stable")
BUILD_DIR=$(pwd)
CLIENT_DIR=$BUILD_DIR/insights/client

git clone git@github.com:gravitypriest/insights-client-runner.git $CLIENT_DIR

# ./build_client_egg.sh
# ./build_client_egg.sh --release
# ./build_client_egg.sh --release --force

# Warn about uncommitted changes and untracked files
# check to make sure tree is clean before checkout (so no uncommitted changes get overwritten)

if [ $? -eq 128 ]
then
    # dir exists
    echo "Could not clone insights-client-runner."
    exit
fi

for ref in ${CLIENT_REFS[@]}
do
    cd $CLIENT_DIR
    git checkout $ref
    CLIENT_VERSION=$(git describe --tags --match '*.*.*')
    echo $CLIENT_VERSION > VERSION      # make sure version tag and VERSION file match
    # handle error if there's no matching version tag for the CLIENT_REFS tags (there should be!!)
    cd $BUILD_DIR

    # rest of the script is the same as it was before, but we create multiple zips
    rm -f insights_$ref.zip
    rm -rf insights_core.egg-info
    cp MANIFEST.in.client MANIFEST.in
    $PYTHON setup.py egg_info
    mkdir -p tmp/EGG-INFO
    cp insights_core.egg-info/* tmp/EGG-INFO
    cp -r insights tmp
    cd tmp
    # remove unneeded bits to save on space
    rm -rf insights/archive
    find insights -path '*tests/*' -delete
    find insights -name '*.pyc' -delete

    git rev-parse --short HEAD > insights/COMMIT

    find . -type f -exec touch -c -t 201801010000.00 {} \;
    find . -type f -exec chmod 0444 {} \;
    find . -type f -print | sort -df | xargs zip -X --no-dir-entries -r ../insights_$ref.zip
    cd ..
    rm -rf tmp
    git checkout MANIFEST.in
done