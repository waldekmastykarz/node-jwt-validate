#!/bin/bash

echo "Updating .js files..."
for file in ./dist/esm/*.js; do
  echo "Updating $file contents..."
  # Use in-place edit correctly for both Linux and macOS
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/\.js'/\.mjs'/g" "$file" # macOS
  else
    sed -i "s/\.js'/\.mjs'/g" "$file"    # Linux
  fi
  echo "Renaming $file to ${file%.js}.mjs..."
  mv "$file" "${file%.js}.mjs"
done
echo

echo "Updating .d.ts files..."
for file in ./dist/esm/*.d.ts; do
  echo "Updating $file contents..."
  # Use in-place edit correctly for both Linux and macOS
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/\.js'/\.mjs'/g" "$file" # macOS
  else
    sed -i "s/\.js'/\.mjs'/g" "$file"    # Linux
  fi
  echo "Renaming $file to ${file%.d.ts}.d.mts..."
  mv "$file" "${file%.d.ts}.d.mts"
done