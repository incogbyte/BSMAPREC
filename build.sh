#!/bin/bash


rm -rf build


gradle jar

echo "Build .jar inside : build/libs/source-map-detector-all.jar"

