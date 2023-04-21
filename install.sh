#! /bin/bash
#
# Copyright (c) 2023-2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
SCRIPT_HOME=$(cd "$(dirname $0)"; pwd)
LOG_PATH=$1
PATCH_TOTAL_NUMBER=0
PATCH_SUCCESSFUL_NUMBER=0
PATCH_FAILED_NUMBER=0

function logInfo()
{
    echo $(date +'%Y-%m-%d %H:%M:%S') \| INFO \| OpenEulerCURL \| $*
}

function logError()
{
    echo $(date +'%Y-%m-%d %H:%M:%S') \| "ERR " \| OpenEulerCURL \| $*
}

function initCurlRepo()
{
    logInfo init OpenEuler Curl
    if [ -f ${SCRIPT_HOME}/curl-7.79.1.tar.xz ]; then
        if [ -d ${SCRIPT_HOME}/curl-7.79.1 ]; then
            logInfo remove exists directory ${SCRIPT_HOME}/curl-7.79.1
            rm -fr ${SCRIPT_HOME}/curl-7.79.1
        fi

        logInfo unzip curl-7.79.1.tar.xz
        pushd ${SCRIPT_HOME}
        tar -xvf ${SCRIPT_HOME}/curl-7.79.1.tar.xz
        popd

        if [ -d ${SCRIPT_HOME}/curl-7.79.1 ]; then
            pushd ${SCRIPT_HOME}/curl-7.79.1
            echo "*.orgi" > .gitignore
            git init
            git add .
            git commit -m "init OpenEuler Curl repo"
            popd
        else
            logError can not unzip OpenEuler Curl tar file ${SCRIPT_HOME}/curl-7.79.1.tar.xz
        fi
    else
        logError OpenEuler Curl tar file does not exists ${SCRIPT_HOME}/curl-7.79.1.tar.xz
    fi
}

function runPatch()
{
    ((PATCH_TOTAL_NUMBER=$PATCH_TOTAL_NUMBER+1))
    PATCH_FILE=$1
    logInfo run patch ${PATCH_FILE}
    pushd ${SCRIPT_HOME}/curl-7.79.1
    git am --signoff --ignore-whitespace ${SCRIPT_HOME}/${PATCH_FILE}
    if [ $? -eq 0 ]; then
        ((PATCH_SUCCESSFUL_NUMBER=$PATCH_SUCCESSFUL_NUMBER+1))
        logInfo  run patch ${PATCH_FILE} successful
    else
        ((PATCH_FAILED_NUMBER=$PATCH_FAILED_NUMBER+1))
        logError run patch ${PATCH_FILE} failed
    fi
    popd
}

function runPatchWithGitApply()
{
    ((PATCH_TOTAL_NUMBER=$PATCH_TOTAL_NUMBER+1))
    PATCH_FILE=$1
    COMMIT_MSG=$2
    logInfo run patch ${PATCH_FILE}
    pushd ${SCRIPT_HOME}/curl-7.79.1
    git apply ${SCRIPT_HOME}/${PATCH_FILE}
    git add .

    logInfo ${COMMIT_MSG}

    git commit -s -m "${COMMIT_MSG}"
    if [ $? -eq 0 ]; then
        ((PATCH_SUCCESSFUL_NUMBER=$PATCH_SUCCESSFUL_NUMBER+1))
        logInfo  run patch ${PATCH_FILE} successful
    else
        ((PATCH_FAILED_NUMBER=$PATCH_FAILED_NUMBER+1))
        logError run patch ${PATCH_FILE} failed
    fi
    popd
}

# CVE commit message
COMMIT_MSG_CVE_2022_27782="tls: check more TLS details for connection reuse

CVE-2022-27782

Reported-by: Harry Sintonen
Bug: https://curl.se/docs/CVE-2022-27782.html"

function runAllPatch()
{
    runPatch backport-0101-curl-7.32.0-multilib.patch
    runPatch backport-CVE-2022-22576.patch
    runPatch backport-CVE-2022-27775.patch
    runPatch backport-CVE-2022-27776.patch
    runPatch backport-pre-CVE-2022-27774.patch
    runPatch backport-001-CVE-2022-27774.patch
    runPatch backport-002-CVE-2022-27774.patch
    runPatch backport-CVE-2022-27781.patch
    runPatch backport-pre-CVE-2022-27782.patch
    # git apply backport-CVE-2022-27782.patch
    runPatchWithGitApply backport-CVE-2022-27782.patch "${COMMIT_MSG_CVE_2022_27782}"
    runPatch backport-CVE-2022-32205.patch
    runPatch backport-CVE-2022-32206.patch
    runPatch backport-CVE-2022-32207.patch
    runPatch backport-CVE-2022-32208.patch
    runPatch backport-fix-configure-disable-http-auth-build-error.patch
    runPatch backport-CVE-2022-35252-cookie-reject-cookies-with-control-bytes.patch
    runPatch backport-CVE-2022-32221.patch
    runPatch backport-CVE-2022-42916.patch
    runPatch backport-CVE-2022-42915.patch
    runPatch backport-CVE-2022-43551-http-use-the-IDN-decoded-name-in-HSTS-checks.patch
    runPatch backport-CVE-2022-43552-smb-telnet-do-not-free-the-protocol-struct-in-_done.patch
    runPatch backport-0001-CVE-2023-23914-CVE-2023-23915.patch
    runPatch backport-0002-CVE-2023-23914-CVE-2023-23915.patch
    runPatch backport-0003-CVE-2023-23914-CVE-2023-23915.patch
    runPatch backport-0004-CVE-2023-23914-CVE-2023-23915.patch
    runPatch backport-0005-CVE-2023-23914-CVE-2023-23915.patch
    runPatch backport-0001-CVE-2023-23916.patch
    runPatch backport-0002-CVE-2023-23916.patch
    runPatch backport-CVE-2023-27533.patch
    runPatch backport-CVE-2023-27534-pre1.patch
    runPatch backport-CVE-2023-27534.patch
    runPatch backport-CVE-2023-27538.patch
    runPatch backport-CVE-2023-27535-pre1.patch
    runPatch backport-CVE-2023-27536.patch
    runPatch backport-CVE-2023-27535.patch
    logInfo run patch ${PATCH_SUCCESSFUL_NUMBER} successful, ${PATCH_FAILED_NUMBER} failed, ${PATCH_TOTAL_NUMBER} total
}

function initLogPath()
{
    logInfo current path is $(pwd)
    if [ -z "$LOG_PATH" ]; then
        LOG_PATH=${SCRIPT_HOME}/openEulerCurl
    fi

    logInfo "create OpenEuler Curl log path ${LOG_PATH}"
    mkdir ${LOG_PATH}
}

function main()
{
    initCurlRepo
    runAllPatch
}

initLogPath
main 2>&1 | tee ${LOG_PATH}/installOpenEurlCurl.log
exit 0