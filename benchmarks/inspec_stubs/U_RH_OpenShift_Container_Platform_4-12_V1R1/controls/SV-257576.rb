control 'SV-257576' do
  title 'OpenShift must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'OpenShift and its components must generate audit records when modifying security objects. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.

Without audit record generation, unauthorized users can modify security objects unknowingly for malicious intent creating vulnerabilities within the container platform.

'
  desc 'check', %q(Verify the Red Hat Enterprise Linux CoreOS (RHCOS) is configured to generate audit records when successful/unsuccessful attempts to modify security categories or objects occur by executing the following:
 
for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e "key=privileged" -e "key=perm_mod" /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node:

-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/restorecon -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=unset -F key=privileged

If the above rules are not listed on each node, this is a finding.)
  desc 'fix', 'Apply the machine config to configure modification audit records by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-modify-categories-secobjects-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
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
          source: data:,-a%20always%2Cexit%20-F%20path%3D/usr/sbin/restorecon%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dprivileged%0A
        mode: 0644
        path: /etc/audit/rules.d/75-usr_sbin_restorecon_execution.rules
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
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61311r921669_chk'
  tag severity: 'medium'
  tag gid: 'V-257576'
  tag rid: 'SV-257576r921671_rule'
  tag stig_id: 'CNTR-OS-000940'
  tag gtitle: 'SRG-APP-000496-CTR-001240'
  tag fix_id: 'F-61235r921670_fix'
  tag satisfies: ['SRG-APP-000496-CTR-001240', 'SRG-APP-000497-CTR-001245', 'SRG-APP-000498-CTR-001250']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
