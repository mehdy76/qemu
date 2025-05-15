/*
 * QEMU Guest Agent Linux-specific command implementations
 *
 * Copyright IBM Corp. 2011
 *
 * Authors:
 *  Michael Roth      <mdroth@linux.vnet.ibm.com>
 *  Michal Privoznik  <mprivozn@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "commands-common.h"
#include "cutils.h"
#include <mntent.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int64_t qmp_guest_set_computer_name(const char *computerName, Error **errp);
int rename_computer(const char *newName);

int64_t qmp_guest_reboot_os(Error **errp);

int64_t qmp_guest_join_domain(const bool isLdap, const char *domainName, const char *domainNetBiosName, const char *domainUserName, const char *domainPassword, const char *domainOU, Error **errp);


#if defined(CONFIG_FSFREEZE) || defined(CONFIG_FSTRIM)
static int dev_major_minor(const char *devpath,
                           unsigned int *devmajor, unsigned int *devminor)
{
    struct stat st;

    *devmajor = 0;
    *devminor = 0;

    if (stat(devpath, &st) < 0) {
        slog("failed to stat device file '%s': %s", devpath, strerror(errno));
        return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        /* It is bind mount */
        return -2;
    }
    if (S_ISBLK(st.st_mode)) {
        *devmajor = major(st.st_rdev);
        *devminor = minor(st.st_rdev);
        return 0;
    }
    return -1;
}

static bool build_fs_mount_list_from_mtab(FsMountList *mounts, Error **errp)
{
    struct mntent *ment;
    FsMount *mount;
    char const *mtab = "/proc/self/mounts";
    FILE *fp;
    unsigned int devmajor, devminor;

    fp = setmntent(mtab, "r");
    if (!fp) {
        error_setg(errp, "failed to open mtab file: '%s'", mtab);
        return false;
    }

    while ((ment = getmntent(fp))) {
        /*
         * An entry which device name doesn't start with a '/' is
         * either a dummy file system or a network file system.
         * Add special handling for smbfs and cifs as is done by
         * coreutils as well.
         */
        if ((ment->mnt_fsname[0] != '/') ||
            (strcmp(ment->mnt_type, "smbfs") == 0) ||
            (strcmp(ment->mnt_type, "cifs") == 0)) {
            continue;
        }
        if (dev_major_minor(ment->mnt_fsname, &devmajor, &devminor) == -2) {
            /* Skip bind mounts */
            continue;
        }

        mount = g_new0(FsMount, 1);
        mount->dirname = g_strdup(ment->mnt_dir);
        mount->devtype = g_strdup(ment->mnt_type);
        mount->devmajor = devmajor;
        mount->devminor = devminor;

        QTAILQ_INSERT_TAIL(mounts, mount, next);
    }

    endmntent(fp);
    return true;
}

static void decode_mntname(char *name, int len)
{
    int i, j = 0;
    for (i = 0; i <= len; i++) {
        if (name[i] != '\\') {
            name[j++] = name[i];
        } else if (name[i + 1] == '\\') {
            name[j++] = '\\';
            i++;
        } else if (name[i + 1] >= '0' && name[i + 1] <= '3' &&
                   name[i + 2] >= '0' && name[i + 2] <= '7' &&
                   name[i + 3] >= '0' && name[i + 3] <= '7') {
            name[j++] = (name[i + 1] - '0') * 64 +
                        (name[i + 2] - '0') * 8 +
                        (name[i + 3] - '0');
            i += 3;
        } else {
            name[j++] = name[i];
        }
    }
}

/*
 * Walk the mount table and build a list of local file systems
 */
bool build_fs_mount_list(FsMountList *mounts, Error **errp)
{
    FsMount *mount;
    char const *mountinfo = "/proc/self/mountinfo";
    FILE *fp;
    char *line = NULL, *dash;
    size_t n;
    char check;
    unsigned int devmajor, devminor;
    int ret, dir_s, dir_e, type_s, type_e, dev_s, dev_e;

    fp = fopen(mountinfo, "r");
    if (!fp) {
        return build_fs_mount_list_from_mtab(mounts, errp);
    }

    while (getline(&line, &n, fp) != -1) {
        ret = sscanf(line, "%*u %*u %u:%u %*s %n%*s%n%c",
                     &devmajor, &devminor, &dir_s, &dir_e, &check);
        if (ret < 3) {
            continue;
        }
        dash = strstr(line + dir_e, " - ");
        if (!dash) {
            continue;
        }
        ret = sscanf(dash, " - %n%*s%n %n%*s%n%c",
                     &type_s, &type_e, &dev_s, &dev_e, &check);
        if (ret < 1) {
            continue;
        }
        line[dir_e] = 0;
        dash[type_e] = 0;
        dash[dev_e] = 0;
        decode_mntname(line + dir_s, dir_e - dir_s);
        decode_mntname(dash + dev_s, dev_e - dev_s);
        if (devmajor == 0) {
            /* btrfs reports major number = 0 */
            if (strcmp("btrfs", dash + type_s) != 0 ||
                dev_major_minor(dash + dev_s, &devmajor, &devminor) < 0) {
                continue;
            }
        }

        mount = g_new0(FsMount, 1);
        mount->dirname = g_strdup(line + dir_s);
        mount->devtype = g_strdup(dash + type_s);
        mount->devmajor = devmajor;
        mount->devminor = devminor;

        QTAILQ_INSERT_TAIL(mounts, mount, next);
    }
    free(line);

    fclose(fp);
    return true;
}
#endif /* CONFIG_FSFREEZE || CONFIG_FSTRIM */

#ifdef CONFIG_FSFREEZE
/*
 * Walk list of mounted file systems in the guest, and freeze the ones which
 * are real local file systems.
 */
int64_t qmp_guest_fsfreeze_do_freeze_list(bool has_mountpoints,
                                          strList *mountpoints,
                                          FsMountList mounts,
                                          Error **errp)
{
    struct FsMount *mount;
    strList *list;
    int fd, ret, i = 0;

    QTAILQ_FOREACH_REVERSE(mount, &mounts, next) {
        /* To issue fsfreeze in the reverse order of mounts, check if the
         * mount is listed in the list here */
        if (has_mountpoints) {
            for (list = mountpoints; list; list = list->next) {
                if (strcmp(list->value, mount->dirname) == 0) {
                    break;
                }
            }
            if (!list) {
                continue;
            }
        }

        fd = qga_open_cloexec(mount->dirname, O_RDONLY, 0);
        if (fd == -1) {
            error_setg_errno(errp, errno, "failed to open %s", mount->dirname);
            return -1;
        }

        /* we try to cull filesystems we know won't work in advance, but other
         * filesystems may not implement fsfreeze for less obvious reasons.
         * these will report EOPNOTSUPP. we simply ignore these when tallying
         * the number of frozen filesystems.
         * if a filesystem is mounted more than once (aka bind mount) a
         * consecutive attempt to freeze an already frozen filesystem will
         * return EBUSY.
         *
         * any other error means a failure to freeze a filesystem we
         * expect to be freezable, so return an error in those cases
         * and return system to thawed state.
         */
        ret = ioctl(fd, FIFREEZE);
        if (ret == -1) {
            if (errno != EOPNOTSUPP && errno != EBUSY) {
                error_setg_errno(errp, errno, "failed to freeze %s",
                                 mount->dirname);
                close(fd);
                return -1;
            }
        } else {
            i++;
        }
        close(fd);
    }
    return i;
}

int qmp_guest_fsfreeze_do_thaw(Error **errp)
{
    int ret;
    FsMountList mounts;
    FsMount *mount;
    int fd, i = 0, logged;
    Error *local_err = NULL;

    QTAILQ_INIT(&mounts);
    if (!build_fs_mount_list(&mounts, &local_err)) {
        error_propagate(errp, local_err);
        return -1;
    }

    QTAILQ_FOREACH(mount, &mounts, next) {
        logged = false;
        fd = qga_open_cloexec(mount->dirname, O_RDONLY, 0);
        if (fd == -1) {
            continue;
        }
        /* we have no way of knowing whether a filesystem was actually unfrozen
         * as a result of a successful call to FITHAW, only that if an error
         * was returned the filesystem was *not* unfrozen by that particular
         * call.
         *
         * since multiple preceding FIFREEZEs require multiple calls to FITHAW
         * to unfreeze, continuing issuing FITHAW until an error is returned,
         * in which case either the filesystem is in an unfreezable state, or,
         * more likely, it was thawed previously (and remains so afterward).
         *
         * also, since the most recent successful call is the one that did
         * the actual unfreeze, we can use this to provide an accurate count
         * of the number of filesystems unfrozen by guest-fsfreeze-thaw, which
         * may * be useful for determining whether a filesystem was unfrozen
         * during the freeze/thaw phase by a process other than qemu-ga.
         */
        do {
            ret = ioctl(fd, FITHAW);
            if (ret == 0 && !logged) {
                i++;
                logged = true;
            }
        } while (ret == 0);
        close(fd);
    }

    free_fs_mount_list(&mounts);

    return i;
}
#endif /* CONFIG_FSFREEZE */

/* wisper code -- linux rename computer*/

int64_t qmp_guest_set_computer_name(const char *computerName, Error **errp){
    int ret = rename_computer(computerName);
    if (ret != 1)
        return ret;
    return 1;
}

int rename_computer(const char *newName) {
    // Check if newName is empty
    if (newName == NULL || newName[0] == '\0') {
        g_debug("Error: New name is empty");
        return 0;
    }

    char command[256];
    sprintf(command, "/usr/bin/hostnamectl set-hostname %s", newName);
    int ret = system(command);
    if (ret == -1) {
        g_debug("Error setting hostname");
        return 0;
    }
    g_debug("Hostname set to %s", newName);
    return 1;
}

int64_t qmp_guest_reboot_os(Error **errp){
    char command[256];
    sprintf(command, "/usr/bin/systemctl reboot");
    int ret = system(command);
    if (ret == -1) {
        g_debug("Error: Failed to execute system reboot command");
        return 0;
    }
    g_debug("System reboot command executed successfully");
    return 1;
}

int64_t qmp_guest_join_domain(const bool isLdap, const char *domainName, const char *domainNetBiosName, const char *domainUserName, const char *domainPassword, const char *domainOU, Error **errp){
    /* example domain junction command: 
    virsh qemu-agent-command --timeout 300 vmName '{"execute":"guest-join-domain","arguments":{"isLdap":false,"domainName":"wsp.corp","domainNetBiosName":"wsp.corp","domainUserName":"user","domainPassword":"password"}}'
    */
    char str_isLdap[10];
    if (isLdap)
        sprintf(str_isLdap, "true");
    else
        sprintf(str_isLdap, "false");

    int leaveStatus = system("/usr/sbin/realm leave");
    if (leaveStatus != 0) {
        g_debug("Error: Failed to leave the domain. Command returned %d.\n", leaveStatus);
    }

    /* char logCommand[1024]; */
    /* sprintf(logCommand,"{\"execute\":\"guest-join-domain\",\"arguments\":{\"isLdap\":%s,\"domainName\":\"%s\", \"domainNetBiosName\":\"%s\",\"domainUserName\":\"%s\",\"domainPassword\":\"XXXXXXXX\"", str_isLdap, domainName, domainNetBiosName,domainUserName); */ 
    /* Join domain now */
    char logCommand[4096];
    sprintf (logCommand, "Joining domain with theses parameters: LDAP: %s - domainName: %s - netBiosName: %s - domainUserName: %s - domainPassword: XXXXXX - domainOU: %s", str_isLdap, domainName, domainNetBiosName,domainUserName, domainOU );
    g_debug("%s\n", logCommand);

    char realmCommand[1024];
    if(domainOU){
        if (isLdap){
            sprintf(realmCommand, "/usr/bin/printf '%s' | /usr/sbin/realm join %s --use-ldaps -U %s --computer-ou=%s", domainPassword, domainName, domainUserName, domainOU);
            g_debug("Running this command: /usr/bin/printf 'XXXXXX' | /usr/sbin/realm join %s --use-ldaps -U %s --computer-ou=%s", domainName, domainUserName, domainOU);
        } else {
            sprintf(realmCommand, "/usr/bin/printf '%s' | /usr/sbin/realm join %s -U %s --computer-ou=%s", domainPassword, domainName, domainUserName, domainOU);
            g_debug("Running this command: /usr/bin/printf 'XXXXXX' | /usr/sbin/realm join %s -U %s --computer-ou=%s", domainName, domainUserName, domainOU);
        }
    } else {
        if (isLdap){
            sprintf(realmCommand, "/usr/bin/printf '%s' | /usr/sbin/realm join %s --use-ldaps -U %s", domainPassword, domainName, domainUserName);
            g_debug("Running this command: /usr/bin/printf 'XXXXXX' | /usr/sbin/realm join %s --use-ldaps -U %s", domainName, domainUserName);
        } else {
            sprintf(realmCommand, "/usr/bin/printf '%s' | /usr/sbin/realm join %s -U %s", domainPassword, domainName, domainUserName);
            g_debug("Running this command: /usr/bin/printf 'XXXXXX' | /usr/sbin/realm join %s -U %s", domainName, domainUserName);
        }        
        
    }
    int ret = system(realmCommand);
    if (ret != 0) {
        g_debug("Error: Failed to join the domain. Command returned %d.\n", ret);
        return 0;
    }
    g_debug("Successfully joined the domain %s with netbios name %s\n", domainName, domainNetBiosName);
    return 1;
}

