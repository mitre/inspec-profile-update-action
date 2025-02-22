control 'SV-257575' do
  title 'OpenShift must generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Audit records provide a crucial source of information for security monitoring and incident response. By generating audit records for privilege modification attempts, OpenShift enables administrators and security teams to track and investigate any unauthorized or suspicious changes to privileges. These records serve as an essential source of evidence for detecting and responding to potential security incidents.

Audit records for unsuccessful attempts to modify privileges help in identifying unauthorized activities or potential attacks. If an unauthorized entity attempts to modify privileges, the audit records can serve as an early warning sign of a security threat. By monitoring and analyzing such records, administrators can detect and mitigate potential security breaches before they escalate.

Audit records play a vital role in forensic analysis and investigation. In the event of a security incident or suspected compromise, audit logs for privilege modifications provide valuable information for understanding the scope and impact of the incident.'
  desc 'check', %q(Verify OpenShift is configured to generate audit records when successful/unsuccessful attempts to modify privileges occur by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e "key=unsuccessful-create" -e "key=unsuccessful-modification"  -e "key=delete" -e "key=unsuccessful-access" -e "actions" -e "key=perm_mod" -e "audit_rules_usergroup_modification"  -e "module-change"  -e "logins" /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node:

-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S open -F a1&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S open -F a1&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S open -F a1&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S open -F a1&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S open -F a1&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S open -F a1&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modmodule-changeification
-a always,exit -F arch=b32 -S open -F a1&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S open -F a1&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-w /etc/sudoers.d -p wa -k actions
-w /etc/sudoers -p wa -k actions
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S delete_module -F key=module-change
-a always,exit -F arch=b64 -S delete_module -F key=module-change
-a always,exit -F arch=b32 -S finit_module -F key=module-change
-a always,exit -F arch=b64 -S finit_module -F key=module-change
-a always,exit -F arch=b32 -S init_module -F key=module-change
-a always,exit -F arch=b64 -S init_module -F key=module-change
-w /var/log/lastlog -p wa -k logins
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod

If the above rules are not listed on each node, this is a finding.)
  desc 'fix', 'Apply the machine config to generate audit records when successful/unsuccessful attempts to modify privileges by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-modify-privileges-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,%23%23%20Make%20the%20loginuid%20immutable.%20This%20prevents%20tampering%20with%20the%20auid.%0A--loginuid-immutable%0A
        mode: 0644
        path: /etc/audit/rules.d/11-loginuid.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20chmod%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20chmod%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-chmod_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20chown%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20chown%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-chown_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20fchmod%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20fchmod%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-fchmod_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20fchmodat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20fchmodat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-fchmodat_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20fchown%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20fchown%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-fchown_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20fchownat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20fchownat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-fchownat_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20fremovexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20fremovexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-fremovexattr_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20fsetxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20fsetxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-fsetxattr_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20lchown%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20lchown%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-lchown_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20lremovexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20lremovexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-lremovexattr_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20lsetxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20lsetxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-lsetxattr_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20removexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20removexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-removexattr_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20setxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20setxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-setxattr_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20umount2%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20umount%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-umount_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20umount2%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20umount2%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-umount2_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/usermod%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_usermod_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/unix_update%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_unix_update_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/kmod%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_kmod_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/setfacl%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_setfacl_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/chacl%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_chacl_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/chcon%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_chcon_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/semanage%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_semanage_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/setfiles%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_setfiles_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/setsebool%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_setsebool_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20rename%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20rename%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A
        mode: 0644
        path: /etc/audit/rules.d/75-rename-file-deletion-events.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20renameat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20renameat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A
        mode: 0644
        path: /etc/audit/rules.d/75-renameat-file-deletion-events.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20rmdir%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20rmdir%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A
        mode: 0644
        path: /etc/audit/rules.d/75-rmdir-file-deletion-events.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20unlink%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20unlink%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A
        mode: 0644
        path: /etc/audit/rules.d/75-unlink-file-deletion-events.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20unlinkat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20unlinkat%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Ddelete%0A
        mode: 0644
        path: /etc/audit/rules.d/75-unlinkat-file-deletion-events.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20delete_module%20-k%20module-change%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20delete_module%20-k%20module-change%0A
        mode: 0644
        path: /etc/audit/rules.d/75-kernel-module-loading-delete.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20finit_module%20-k%20module-change%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20finit_module%20-k%20module-change%0A
        mode: 0644
        path: /etc/audit/rules.d/75-kernel-module-loading-finit.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20init_module%20-k%20module-change%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20init_module%20-k%20module-change%0A
        mode: 0644
        path: /etc/audit/rules.d/75-kernel-module-loading-init.rules
        overwrite: true
      - contents:
          source: data:,-w%20/var/log/lastlog%20-p%20wa%20-k%20logins%0A
        mode: 0644
        path: /etc/audit/rules.d/75-lastlog_login_events.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20mount%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20mount%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-mount_dac_modification.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/chage%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_chage_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/chsh%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_chsh_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/crontab%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_crontab_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/gpasswd%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_gpasswd_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/newgrp%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_newgrp_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/pam_timestamp_check%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_pam_timestamp_check_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/passwd%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_passwd_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/libexec/openssh/ssh-keysign%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_libexec_openssh_ssh-keysign_execution.rules
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
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/sudoedit%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_sudoedit_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/unix_chkpwd%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_unix_chkpwd_execution.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/userhelper%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_userhelper_execution.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/sudoers.d/%20-p%20wa%20-k%20actions%0A-w%20/etc/sudoers%20-p%20wa%20-k%20actions%0A
        mode: 0644
        path: /etc/audit/rules.d/75-audit-sysadmin-actions.rules
        overwrite: true
      - contents:
          source: data:,%23%23%20This%20content%20is%20a%20section%20of%20an%20Audit%20config%20snapshot%20recommended%20for%20Red%2520Hat%2520Enterprise%2520Linux%2520CoreOS%25204%20systems%20that%20target%20OSPP%20compliance.%0A%23%23%20The%20following%20content%20has%20been%20retreived%20on%202019-03-11%20from%3A%20https%3A//github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules%0A%0A%23%23%20The%20purpose%20of%20these%20rules%20is%20to%20meet%20the%20requirements%20for%20Operating%0A%23%23%20System%20Protection%20Profile%20%28OSPP%29v4.2.%20These%20rules%20depends%20on%20having%0A%23%23%2010-base-config.rules%2C%2011-loginuid.rules%2C%20and%2043-module-load.rules%20installed.%0A%0A%23%23%20Unsuccessful%20file%20creation%20%28open%20with%20O_CREAT%29%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20creat%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20creat%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20creat%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20creat%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A%0A%23%23%20Unsuccessful%20file%20modifications%20%28open%20for%20write%20or%20truncate%29%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A%0A%23%23%20Unsuccessful%20file%20access%20%28any%20other%20opens%29%20This%20has%20to%20go%20last.%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A
        mode: 0644
        path: /etc/audit/rules.d/30-ospp-v42-remediation.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/group%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_group_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/gshadow%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_gshadow_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/security/opasswd%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_security_opasswd_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/passwd%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_passwd_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/shadow%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_shadow_usergroup_modification.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61310r921666_chk'
  tag severity: 'medium'
  tag gid: 'V-257575'
  tag rid: 'SV-257575r921668_rule'
  tag stig_id: 'CNTR-OS-000930'
  tag gtitle: 'SRG-APP-000495-CTR-001235'
  tag fix_id: 'F-61234r921667_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
