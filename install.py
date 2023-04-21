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
import os
import shutil
import sys
import time
import traceback

class CurlLog:
    _isDebug = True
    _f = None
    @staticmethod
    def initLogger(logPath):
        if not os.path.exists(logPath):
            os.makedirs(logPath)
        CurlLog._f = open(os.path.join(logPath, "installOpenEurlCurl.log"), "w")
        pass

    @staticmethod
    def close():
        if CurlLog._f is None:
            return;
        CurlLog._f.close()

    @staticmethod
    def __getCurrentTime():
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    @staticmethod
    def info(info):
        content = "%s | INFO | OpenEulerCurl | %s"%(CurlLog.__getCurrentTime(), info)
        CurlLog._f.write("%s\n" % (content))
        if CurlLog._isDebug:
            print(content)
        pass

    @staticmethod
    def error(error):
        content = "%s | ERR  | OpenEulerCurl | %s"%(CurlLog.__getCurrentTime(), error)
        CurlLog._f.write("%s\n" % (content))
        if CurlLog._isDebug:
            print(content)
        pass

    @staticmethod
    def exception(error):
        stack = traceback.format_exc()
        content = "%s | ERR  | OpenEulerCurl | %s"%(CurlLog.__getCurrentTime(), stack)
        CurlLog._f.write("%s\n" % (content))
        if CurlLog._isDebug:
            print(content)
        pass


class Patch:
    _patchPath = None
    _sourcePath = None
    _allPatchs = [
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
        "backport-CVE-2023-27535.patch"
    ]

    _myPatchs = [
        "001_add_have_fchmod_macro_for_fopen.patch"
    ]

    @staticmethod
    def init(patchPath, sourcePath):
        Patch._patchPath = patchPath
        Patch._sourcePath = sourcePath
        pass

    @staticmethod
    def _doPatch(patchPath, patch):
        patchFile = os.path.join(patchPath, patch)
        if os.path.exists(patchFile):
            cmd = "cd %s; patch -p1 < %s 2>&1" % (Patch._sourcePath, patchFile)
            messages = os.popen(cmd).readlines()
            if len(messages) == 0:
                CurlLog.info("patch result empty")
                pass
            for message in messages:
                CurlLog.info("patch result [%s]" % (message.rstrip()))
        else:
            CurlLog.error("patch does not exits %s" % (patchFile))
        pass

    @staticmethod
    def patchAll():
        count = 0
        for patch in Patch._allPatchs:
            count = count + 1
            CurlLog.info("the OpenEuler Curl's %d patch %s" % (count, patch))
            Patch._doPatch(Patch._patchPath, patch)
            pass

        myPathchPath = os.path.join(Patch._patchPath, "customized", "patch")
        for patch in Patch._myPatchs:
            count = count + 1
            CurlLog.info("my OpenEuler Curl's %d patch %s" % (count, patch))
            Patch._doPatch(myPathchPath, patch)
        pass


class Installer:
    _tarFileName = "curl-7.79.1.tar.xz"
    _openEulerCurlSourcePath = "curl-7.79.1"
    def __init__(self, scriptHome):
        self.scriptHome = scriptHome
        Patch.init(self.scriptHome, os.path.join(self.scriptHome, Installer._openEulerCurlSourcePath))
        pass

    def __unzipOpenCurlTar(self):
        fileName = os.path.join(self.scriptHome, Installer._tarFileName)
        sourcePath = os.path.join(self.scriptHome, Installer._openEulerCurlSourcePath)
        try:
            if os.path.exists(sourcePath):
                cTime = os.path.getctime(sourcePath)
                nowTime = time.time()
                diffTime = int(abs(nowTime - cTime))
                if diffTime > 300: # create the directory is too old
                    CurlLog.info("remove OpenEuler Curl source path %s" % (sourcePath))
                    shutil.rmtree(sourcePath)
                    CurlLog.info("remove source path successful")
                else:
                    CurlLog.info("it's too new so does not need to remove OpenEuler Curl source path %s" % (sourcePath))
                    return 1

            messages = os.popen("cd %s; tar -xvf %s 2>&1" % (self.scriptHome, Installer._tarFileName)).readlines()
            for message in messages:
                CurlLog.info("tar result=[%s]" % (message.rstrip()));

            if os.path.exists(sourcePath) is False:
                CurlLog.error("can not unzip OpenEuler Curl tar %s" % (fileName))
                return -1

            CurlLog.info("unzip OpenEuler Curl tar successful %s" % (fileName))

            srcIncludePath = os.path.join(sourcePath, "include")
            destIncludePath = os.path.join(self.scriptHome, "include")

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

    def __initRepo(self):
        return self.__unzipOpenCurlTar()

    def install(self):
        CurlLog.info("create OpenEuler Curl repo")
        ret = self.__initRepo()
        if ret == 1:
            CurlLog.info("reuse the soruce path %s" % (Installer._openEulerCurlSourcePath))
            return
        elif ret == -1:
            CurlLog.info("create OpenEuler Curl repo failed")
            return

        CurlLog.info("patch OpenEuler Curl")
        Patch.patchAll()
        CurlLog.info("OpenEuler Curl has been install")
        pass


def main():
    scriptHome = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser()
    parser.add_argument('--gen-dir', help='generate path of log', required=True)
    args = parser.parse_args()

    CurlLog.initLogger(os.path.join(args.gen_dir, "openEulerCurl"))
    CurlLog.info("script path is %s, log path is %s" % (scriptHome, args.gen_dir))
    installer = Installer(scriptHome)
    installer.install()
    CurlLog.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())