// IUserService.aidl — Shizuku user-service binder interface (bd rsh-a88j absorb-D).
//
// Methods on this interface execute in the Shizuku-bridged remote process
// (uid=0 when Shizuku started via Magisk root, uid=2000 when started via ADB).
// Our app binds this service via Shizuku.bindUserService() and then invokes
// the methods through the binder — runCmd() / installApk() are therefore
// privileged shell-equivalent ops, not subject to the normal untrusted_app
// SELinux restrictions.
//
// destroy() is the standard Shizuku-required cleanup hook — transaction
// code 16777114 is reserved by the framework for service teardown.
package it.mdp.mrsh;

interface IUserService {
    void destroy() = 16777114;
    String runCmd(in String[] argv) = 1;
    int installApk(String apkPath) = 2;
}
