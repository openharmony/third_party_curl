#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import fcntl
import os
import shutil
import sys
import time
import traceback

class CurlLog:
    IS_DEBUG = True
    _f = None

    @staticmethod
    def init_logger(log_path):
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        CurlLog._f = open(os.path.join(log_path, "installOpenEurlCurl.log"), "w")
        pass

    @staticmethod
    def close():
        if CurlLog._f is None:
            return;
        CurlLog._f.close()

    @staticmethod
    def __get_current_time():
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    @staticmethod
    def info(info):
        content = "%s | INFO | OpenEulerCurl | %s" % (CurlLog.__get_current_time(), info)
        CurlLog._f.write("%s\n" % (content))
        if CurlLog.IS_DEBUG:
            print(content)
        pass

    @staticmethod
    def error(error):
        content = "%s | ERR  | OpenEulerCurl | %s" % (CurlLog.__get_current_time(), error)
        CurlLog._f.write("%s\n" % (content))
        if CurlLog.IS_DEBUG:
            print(content)
        pass

    @staticmethod
    def exception(error):
        stack = traceback.format_exc()
        content = "%s | ERR  | OpenEulerCurl | %s" % (CurlLog.__get_current_time(), stack)
        CurlLog._f.write("%s\n" % (content))
        if CurlLog.IS_DEBUG:
            print(content)
        pass


class Patch:
    _patch_path = None
    _source_path = None
    _all_patchs = [
        "backport-0101-curl-7.32.0-multilib.patch",
        "backport-CVE-2022-22576.patch",
        "backport-CVE-2022-27775.patch",
        "backport-CVE-2022-27776.patch",
        "backport-pre-CVE-2022-27774.patch",
        "backport-001-CVE-2022-27774.patch",
        "backport-002-CVE-2022-27774.patch",
        "backport-CVE-2022-27781.patch",
        "backport-pre-CVE-2022-27782.patch",
        "backport-CVE-2022-27782.patch",
        "backport-CVE-2022-32205.patch",
        "backport-CVE-2022-32206.patch",
        "backport-CVE-2022-32207.patch",
        "backport-CVE-2022-32208.patch",
        "backport-fix-configure-disable-http-auth-build-error.patch",
        "backport-CVE-2022-35252-cookie-reject-cookies-with-control-bytes.patch",
        "backport-CVE-2022-32221.patch",
        "backport-CVE-2022-42916.patch",
        "backport-CVE-2022-42915.patch",
        "backport-CVE-2022-43551-http-use-the-IDN-decoded-name-in-HSTS-checks.patch",
        "backport-CVE-2022-43552-smb-telnet-do-not-free-the-protocol-struct-in-_done.patch",
        "backport-0001-CVE-2023-23914-CVE-2023-23915.patch",
        "backport-0002-CVE-2023-23914-CVE-2023-23915.patch",
        "backport-0003-CVE-2023-23914-CVE-2023-23915.patch",
        "backport-0004-CVE-2023-23914-CVE-2023-23915.patch",
        "backport-0005-CVE-2023-23914-CVE-2023-23915.patch",
        "backport-0001-CVE-2023-23916.patch",
        "backport-0002-CVE-2023-23916.patch",
        "backport-CVE-2023-27533.patch",
        "backport-CVE-2023-27534-pre1.patch",
        "backport-CVE-2023-27534.patch",
        "backport-CVE-2023-27538.patch",
        "backport-CVE-2023-27535-pre1.patch",
        "backport-CVE-2023-27536.patch",
        "backport-CVE-2023-27535.patch",
        "backport-after-CVE-2022-32207-to-fix-build-error-when-user-don-t-use-glibc.patch",
        "backport-CVE-2023-28321.patch",
        "backport-CVE-2023-28322.patch"
    ]

    _my_patchs = [
    ]

    @staticmethod
    def init(patch_path, source_path):
        Patch._patch_path = patch_path
        Patch._source_path = source_path
        pass

    @staticmethod
    def _do_patch(patch_path, patch):
        patch_file = os.path.join(patch_path, patch)
        if os.path.exists(patch_file):
            cmd = "cd %s; patch -p1 < %s 2>&1" % (Patch._source_path, patch_file)
            messages = os.popen(cmd).readlines()
            if len(messages) == 0:
                CurlLog.info("patch result empty")
                pass
            for message in messages:
                CurlLog.info("patch result [%s]" % (message.rstrip()))
        else:
            CurlLog.error("patch does not exits %s" % (patch_file))
        pass

    @staticmethod
    def patch_all():
        count = 0
        for patch in Patch._all_patchs:
            count = count + 1
            CurlLog.info("the OpenEuler Curl's %d patch %s" % (count, patch))
            Patch._do_patch(Patch._patch_path, patch)
            pass

        my_pathch_path = os.path.join(Patch._patch_path, "customized", "patch")
        for patch in Patch._my_patchs:
            count = count + 1
            CurlLog.info("my OpenEuler Curl's %d patch %s" % (count, patch))
            Patch._do_patch(my_pathch_path, patch)
        pass


class Installer:
    _tar_file_name = "curl-7.79.1.tar.xz"
    _open_euler_curl_source_path = "curl-7.79.1"
    _read_me = "README.OpenSource"

    def __init__(self, script_home):
        self.script_home = script_home
        Patch.init(self.script_home, os.path.join(self.script_home, Installer._open_euler_curl_source_path))
        pass

    def __unzip_open_curl_tar(self):
        fileName = os.path.join(self.script_home, Installer._tar_file_name)
        source_path = os.path.join(self.script_home, Installer._open_euler_curl_source_path)
        try:
            if os.path.exists(source_path):
                cTime = os.path.getctime(source_path)
                nowTime = time.time()
                diffTime = int(abs(nowTime - cTime))
                if diffTime > 300: # create the directory is too old
                    CurlLog.info("remove OpenEuler Curl source path %s" % (source_path))
                    shutil.rmtree(source_path)
                    CurlLog.info("remove source path successful")
                else:
                    CurlLog.info("it's too new, does not need to remove OpenEuler Curl source path %s" % (source_path))
                    return 1

            messages = os.popen("cd %s; tar -xvf %s 2>&1" % (self.script_home, Installer._tar_file_name)).readlines()
            for message in messages:
                CurlLog.info("tar result=[%s]" % (message.rstrip()));

            if os.path.exists(source_path) is False:
                CurlLog.error("can not unzip OpenEuler Curl tar %s" % (fileName))
                return -1

            CurlLog.info("unzip OpenEuler Curl tar successful %s" % (fileName))

            srcIncludePath = os.path.join(source_path, "include")
            destIncludePath = os.path.join(self.script_home, "include")

            if os.path.exists(destIncludePath):
                shutil.rmtree(destIncludePath)
                CurlLog.info("remove include path successful")
                pass

            CurlLog.info("copy include from %s to %s" % (srcIncludePath, destIncludePath))
            result = shutil.copytree(srcIncludePath, destIncludePath)
            CurlLog.info("copy result [%s]" % (result))

            return 0
        except Exception as e:
            CurlLog.error("can not unzip OpenEuler Curl tar %s" % (fileName))
            CurlLog.exception(e)
            return -1

    def __init_repo(self):
        return self.__unzip_open_curl_tar()

    def __install(self):
        CurlLog.info("create OpenEuler Curl repo")
        ret = self.__init_repo()
        if ret == 1:
            CurlLog.info("reuse the soruce path %s" % (Installer._open_euler_curl_source_path))
            return
        elif ret == -1:
            CurlLog.info("create OpenEuler Curl repo failed")
            return

        CurlLog.info("patch OpenEuler Curl")
        Patch.patch_all()
        CurlLog.info("OpenEuler Curl has been install")
        pass

    def install(self):
        fileName = os.path.join(self.script_home, Installer._read_me)
        with open(fileName, "r") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            CurlLog.info("only me to install OpenEuler Curl")
            self.__install()
            fcntl.flock(f, fcntl.LOCK_UN)
        pass


def main():
    script_home = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser()
    parser.add_argument('--gen-dir', help='generate path of log', required=True)
    args = parser.parse_args()

    CurlLog.init_logger(os.path.join(args.gen_dir, "openEulerCurl"))
    CurlLog.info("script path is %s, log path is %s" % (script_home, args.gen_dir))
    installer = Installer(script_home)
    installer.install()
    CurlLog.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())