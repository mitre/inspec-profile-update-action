control 'SV-257512' do
  title 'Open Shift must automatically audit account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to remove authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', %q(Verify the audit rules capture the execution of setuid and setgid binaries by executing the following:
 
for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e key=privileged /etc/audit/audit.rules || echo "not found"' 2>/dev/null; done

If "not found" is printed, this is a finding.

Confirm the following rules exist on each node:

-a always,exit -S all -F path=/usr/libexec/dbus-1/dbus-daemon-launch-helper -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/sbin/grub2-set-bootflag -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/fusermount3 -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/fusermount -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/mount -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/passwd -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/pkexec -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/sudo -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/su -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/umount -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/bin/write -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/libexec/sssd/krb5_child -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/libexec/sssd/ldap_child -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/libexec/sssd/proxy_child -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/libexec/sssd/selinux_child -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/libexec/utempter -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/sbin/mount.nfs -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -S all -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=unset -F key=privileged

To find all setuid binaries on the system, execute the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null'; done

If any setuid binary does not have a corresponding audit rule, this is a finding.)
  desc 'fix', 'Apply the machine config by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-setuid-setgid-binaries-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/chage%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_chage_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/fusermount%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_fusermount_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/fusermount3%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_fusermount3_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/gpasswd%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_gpasswd_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/mount%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_mount_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/newgrp%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_newgrp_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/passwd%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_passwd_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/pkexec%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_pkexec_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/su%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_su_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/sudo%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_sudo_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/umount%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_umount_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/lib/polkit-1/polkit-agent-helper-1%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_lib_polkit_helper_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/libexec/dbus-1/dbus-daemon-launch-helper%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-dbus_daemon_launch_helper.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/libexec/sssd/krb5_child%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_libexec_sssd_krb5_child.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/libexec/sssd/ldap_child%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_libexec_sssd_ldap_child.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/libexec/sssd/proxy_child%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_libexec_sssd_proxy_child.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/libexec/sssd/selinux_child%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_libexec_sssd_selinux_child.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/grub2-set-bootflag%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-grub2_set_bootflag.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/mount.nfs%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_mount_nfs.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/pam_timestamp_check%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_pam_timestamp_check.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/unix_chkpwd%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_unix_chkpwd.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61247r921477_chk'
  tag severity: 'medium'
  tag gid: 'V-257512'
  tag rid: 'SV-257512r921479_rule'
  tag stig_id: 'CNTR-OS-000080'
  tag gtitle: 'SRG-APP-000029-CTR-000085'
  tag fix_id: 'F-61171r921478_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
