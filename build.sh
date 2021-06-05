#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.

set -e
CURRENT_DIR=$(dirname "$0")

echo "add curl patch..."

if [ "$1" = "liteos_m" ]; then
    cp -f $CURRENT_DIR/lib/curl_config_liteos_m.h $CURRENT_DIR/lib/curl_config.h
else
    cp -f $CURRENT_DIR/lib/curl_config_liteos_a.h $CURRENT_DIR/lib/curl_config.h
fi

