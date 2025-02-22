control 'SV-257577' do
  title 'OpenShift must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Audit records for unsuccessful attempts to delete privileges help in identifying unauthorized activities or potential attacks. If an unauthorized entity attempts to remove privileges, the audit records can serve as an early warning sign of a security threat. By monitoring and analyzing such records, administrators can detect and mitigate potential security breaches before they escalate.

Audit records play a vital role in forensic analysis and investigation. In the event of a security incident or suspected compromise, audit logs for privilege deletions provide valuable information for understanding the scope and impact of the incident.'
  desc 'check', %q(Verify OpenShift is configured to generate audit records when successful/unsuccessful attempts to delete security privileges occur by executing the following:
 
for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e "key=delete" -e "key=perm_mod" -e "key=privileged" -e "audit_rules_usergroup_modification" /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node:

-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
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
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/passwd -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/sudoedit -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/su -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/libexec/pt_chown -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/userhelper -F auid>=1000 -F auid!=unset -F key=privileged

If the above rules are not listed on each node, this is a finding.)
  desc 'fix', 'Apply the machine config to generate audit records when successful/unsuccessful attempts to delete security privileges by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-delete-privileges-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
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
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20removexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20removexattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-removexattr_dac_modification.rules
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
          source: data:,-w%20/etc/sudoers.d/%20-p%20wa%20-k%20actions%0A-w%20/etc/sudoers%20-p%20wa%20-k%20actions%0A
        mode: 0644
        path: /etc/audit/rules.d/75-audit-sysadmin-actions.rules
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
  tag check_id: 'C-61312r921672_chk'
  tag severity: 'medium'
  tag gid: 'V-257577'
  tag rid: 'SV-257577r921674_rule'
  tag stig_id: 'CNTR-OS-000950'
  tag gtitle: 'SRG-APP-000499-CTR-001255'
  tag fix_id: 'F-61236r921673_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
