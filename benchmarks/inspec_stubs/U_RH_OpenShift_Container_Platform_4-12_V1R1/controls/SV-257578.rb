control 'SV-257578' do
  title 'OpenShift must generate audit records when successful/unsuccessful attempts to delete security objects occur.'
  desc 'By generating audit records for security object deletions, OpenShift enables administrators and security teams to track and investigate any unauthorized or suspicious removal of security objects. These records serve as valuable evidence for detecting and responding to potential security incidents.

Audit records for unsuccessful attempts to delete security objects help in identifying unauthorized activities or potential attacks. If an unauthorized entity attempts to delete security objects, the audit records can serve as an early warning sign of a security threat. By monitoring and analyzing such records, administrators can detect and mitigate potential security breaches before they escalate.

Audit records play a vital role in forensic analysis and investigation. In the event of a security incident or suspected compromise, audit logs for security object deletions provide valuable information for understanding the scope and impact of the incident.

'
  desc 'check', %q(Verify the Red Hat Enterprise Linux CoreOS (RHCOS) is configured to generate audit records when successful/unsuccessful attempts to delete security objects or categories of information occur by executing the following:
 
for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep  -e "key=access" -e "key=delete" -e "key=unsuccessful-delete"  -e "key=privileged" -e "key=perm_mod" /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node:

-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete
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
-a always,exit -F arch=b64 -S renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S rename -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S rename -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S rename -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S unlinkat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S unlinkat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S unlinkat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S unlink -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S unlink -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S unlink -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
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
  desc 'fix', 'Apply the machine config to generate audit records when security objects or categories are deleted by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-delete-sec-objects-levels-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,%23%23%20Unsuccessful%20file%20delete%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20unlink%2Cunlinkat%2Crename%2Crenameat%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-delete%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20unlink%2Cunlinkat%2Crename%2Crenameat%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-delete%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20unlink%2Cunlinkat%2Crename%2Crenameat%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-delete%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20unlink%2Cunlinkat%2Crename%2Crenameat%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-delete%0A
        mode: 0644
        path: /etc/audit/rules.d/30-ospp-v42-4-delete-failed.rules
        overwrite: true
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20fsetxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20fsetxattr%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dperm_mod%0A
        mode: 0644
        path: /etc/audit/rules.d/75-fsetxattr_dac_modification.rules
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
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/chcon%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_chcon_execution.rules
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
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/bin/chage%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_bin_chage_execution.rules
        overwrite: true
" ; done | oc apply -f -'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61313r921675_chk'
  tag severity: 'medium'
  tag gid: 'V-257578'
  tag rid: 'SV-257578r921677_rule'
  tag stig_id: 'CNTR-OS-000960'
  tag gtitle: 'SRG-APP-000501-CTR-001265'
  tag fix_id: 'F-61237r921676_fix'
  tag satisfies: ['SRG-APP-000501-CTR-001265', 'SRG-APP-000502-CTR-001270']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
