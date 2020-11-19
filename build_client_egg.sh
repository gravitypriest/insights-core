#!/bin/bash
PYTHON=${1:-python}
CLIENT_REFS=("nightly" "beta" "stable")
BUILD_DIR=$(mktemp -d -t insights-core-egg-build-XXXXXXXX)
OUTPUT_DIR=$(pwd)
CORE_DIR=$BUILD_DIR/insights-core
CORE_ASSETS_DIR=$BUILD_DIR/insights-core-assets
PLUGINS_DIR=$BUILD_DIR/insights-plugins
PRODSEC_RULES_DIR=$BUILD_DIR/insights-prodsec-rules
CLIENT_DIR=$CORE_DIR/insights/client

cd $BUILD_DIR

# clone repos
git clone git@github.com:gravitypriest/insights-core.git
if [ $? -ne 0 ]; then exit; fi
git clone git@gitlab.cee.redhat.com:prodsec/insights-prodsec-rules.git
if [ $? -ne 0 ]; then exit; fi
git clone git@gitlab.cee.redhat.com:insights-rules/insights-plugins.git
if [ $? -ne 0 ]; then exit; fi
git clone git@gitlab.cee.redhat.com:insights-release-eng/insights-core-assets.git
if [ $? -ne 0 ]; then exit; fi

# do the filters and uploader_json_map.json here
# ASSUMES RELEASE IS READY TO GO AND THE INSIGHTS-CORE-ASSETS
#   UPLOADER_JSON BRANCH IS STAGED WITH CHANGES. NOT MY FAULT IF IT'S NOT

cd $PLUGINS_DIR
$PYTHON setup.py bootstrap
source bin/activate
pip3 install -e $CORE_DIR
pip3 install -e $PRODSEC_RULES_DIR

echo "Generating filters.yaml for insights-core..."
$PYTHON -m insights.tools.apply_spec_filters $CORE_ASSETS_DIR/uploader.json telemetry.rules.plugins prodsec.rules
$PYTHON -m insights.tools.apply_spec_filters $CORE_ASSETS_DIR/uploader.v2.json telemetry.rules.plugins prodsec.rules
deactivate

# verify filters.yaml was created
if [ ! -e $CORE_DIR/insights/filters.yaml ]; then
    echo "ERROR: filters.yaml not found. Somebody set up us the bomb."
    exit
fi

# copy uploader.json to uploader_json_map.json
cp $CORE_ASSETS_DIR/uploader.v2.json $CORE_DIR/uploader_json_map.json

git clone git@github.com:gravitypriest/insights-client-runner.git $CLIENT_DIR
if [ $? -ne 0 ]; then exit; fi

# build for each branch
for ref in ${CLIENT_REFS[@]}
do
    cd $CLIENT_DIR
    git checkout -f $ref
    CLIENT_VERSION=$(git describe --tags --exact-match --match '[0-9]*.[0-9]*.[0-9]*')
    # handle error if there's no matching version tag for the CLIENT_REFS tags (there should be!!)
    if [ $? -ne 0 ]; then
        echo "ERROR: No N.V.R-formatted version tag found. Make sure $ref HEAD is a commit tagged with a version."
        exit
    fi

    # make sure version tag is written to VERSION (it's "dev" in the repo)
    echo $CLIENT_VERSION > VERSION
    cd $CORE_DIR

    # run unit test to make sure everything in the uploader.json map is peachy
    #   (check for any missing specs or ones that need to be renamed)
    $PYTHON -m pytest -p no:cacheprovider $CORE_DIR/insights/tests/client/collection_rules/test_map_components.py

    if [ $? -ne 0 ]; then
        echo "Error verifying uploader.json map. Update the unit test to allow any missing specs, or modify map_components if any need to be renamed."
        exit
    fi

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
    # delete the git metadata from insights/client
    find insights/client -path '*.git/*' -delete

    git rev-parse --short HEAD > insights/COMMIT

    find . -type f -exec touch -c -t 201801010000.00 {} \;
    find . -type f -exec chmod 0444 {} \;
    find . -type f -print | sort -df | xargs zip -X --no-dir-entries -r ../insights_$ref.zip
    cd ..
    rm -rf tmp
    git checkout MANIFEST.in

    mv insights_$ref.zip $OUTPUT_DIR
done

rm -rf $BUILD_DIR
