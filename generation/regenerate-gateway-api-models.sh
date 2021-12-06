#!/bin/sh

set -e

# NB - as currently written, this script has only been tested on Mac OSX
# In particular, Mac makes use of a variant of sed which might not work on other UNIX variants

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

#############
# VARIABLES #
#############

packageVersion='0.1.20' # This needs bumping every time
packageName='RadixGatewayApi.Generated'
outputDirectory="../generated-dependencies"
packageVersionLocation="../Directory.Packages.props"
specName='./gateway-api-spec.yaml'

##########
# CHECKS #
##########

if [ -d $outputDirectory ]; then
  existsCheck=`ls "$outputDirectory" | grep $packageVersion` || true
else
  existsCheck=''
fi

if [ ! -z "$existsCheck" ]; then
    echo "Package $packageName with version $packageVersion has already been built."
    echo "You should bump the version in regenerate-transactions-client.sh so that NuGeT doesn't cache the previous version (which can interfere with your IDE)."
    echo "If you wish to ignore this error, just delete the old package from the $outputDirectory folder."
    exit 1
fi

#########
# REGEN #
#########

# Find dummy diectory
for TMPDIR in "$TMPDIR" "$TMP" /var/tmp /tmp
do
    test -d "$TMPDIR" && break
done

dummyApiDirectory="$TMPDIR/radix-generated-gateway-api/"

rm -rf "$dummyApiDirectory"
mkdir "$dummyApiDirectory"

openapi-generator generate \
    -i "$specName" \
    -g csharp-netcore \
    -o "$dummyApiDirectory" \
    --library httpclient \
    --additional-properties=packageName=$packageName,targetFramework=net5.0,packageVersion=$packageVersion,optionalEmitDefaultValues=true

# Fix various issues in the generated code
for f in `find $dummyApiDirectory -name '*.cs'`; do
  if (grep -q "in BaseValidate(" $f) && [[ $f != *"/obj/"* ]]; then
    awk '{sub(/in BaseValidate/,"in base.BaseValidate"); print}' $f > $f.out
    mv $f.out $f
    echo "$f - Performed BaseValidate fix to source code"
  fi
done

cd "$dummyApiDirectory"
dotnet pack

cd "$SCRIPT_DIR"
mkdir -p "$outputDirectory"

# Tidy up old versions
find "$outputDirectory" -name "$packageName.*.nupkg" -exec rm {} \;

# Create new versions
find "$dummyApiDirectory/src/$packageName/bin/Debug" -name "*.nupkg" -exec cp {} "$outputDirectory" \;

# Clear up generated api directory
rm -rf "$dummyApiDirectory"

# Update the version in the packages listing
sed -i.bu -e "s/Include=\"$packageName\" Version=\"[^\"]*\"/Include=\"$packageName\" Version=\"$packageVersion\"/" "$packageVersionLocation"
rm "$packageVersionLocation.bu" # Clear up the back up file from sed if it completes successfully
