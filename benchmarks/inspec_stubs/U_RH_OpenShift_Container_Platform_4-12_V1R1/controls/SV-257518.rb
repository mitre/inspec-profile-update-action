control 'SV-257518' do
  title 'OpenShift must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'OpenShift and its components must generate audit records successful/unsuccessful attempts to access or delete security objects, security levels, and privileges occur.

All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.

Without audit record generation, access controls levels can be accessed by unauthorized users unknowingly for malicious intent, creating vulnerabilities within the container platform.

'
  desc 'check', %q(Verify OpenShift is configured to generate audit records when successful/unsuccessful attempts to access or delete security objects, security levels, and privileges occur by executing the following:
 
for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e "key=perm_mod" -e "key=unsuccessful-create"  -e "key=unsuccessful-modification" -e "key=unsuccessful-access" /etc/audit/audit.rules|| echo "not found"' 2>/dev/null; done

Confirm the following rules exist on each node:
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S open -F a1&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S open -F a1&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S open -F a1&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S open -F a1&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x40 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S open -F a1&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S open -F a1&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S open -F a1&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S open -F a1&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0x203 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-create
-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification
-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-modification

On each node, if the above rules are not listed, or the return is "not found", this is a finding.)
  desc 'fix', 'Apply the machine config to generate audit records by executing following:

 for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-access-privileges-rules-$mcpool
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
          source: data:,%23%23%20This%20content%20is%20a%20section%20of%20an%20Audit%20config%20snapshot%20recommended%20for%20Red%2520Hat%2520Enterprise%2520Linux%2520CoreOS%25204%20systems%20that%20target%20OSPP%20compliance.%0A%23%23%20The%20following%20content%20has%20been%20retreived%20on%202019-03-11%20from%3A%20https%3A//github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules%0A%0A%23%23%20The%20purpose%20of%20these%20rules%20is%20to%20meet%20the%20requirements%20for%20Operating%0A%23%23%20System%20Protection%20Profile%20%28OSPP%29v4.2.%20These%20rules%20depends%20on%20having%0A%23%23%2010-base-config.rules%2C%2011-loginuid.rules%2C%20and%2043-module-load.rules%20installed.%0A%0A%23%23%20Unsuccessful%20file%20creation%20%28open%20with%20O_CREAT%29%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%260100%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20creat%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20creat%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20creat%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20creat%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-create%0A%0A%23%23%20Unsuccessful%20file%20modifications%20%28open%20for%20write%20or%20truncate%29%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20openat%2Copen_by_handle_at%20-F%20a2%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%20-F%20a1%2601003%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20truncate%2Cftruncate%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-modification%0A%0A%23%23%20Unsuccessful%20file%20access%20%28any%20other%20opens%29%20This%20has%20to%20go%20last.%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EACCES%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20open%2Ccreat%2Ctruncate%2Cftruncate%2Copenat%2Copen_by_handle_at%20-F%20exit%3D-EPERM%20-F%20auid%3E%3D1000%20-F%20auid%21%3Dunset%20-F%20key%3Dunsuccessful-access%0A
        mode: 0644
        path: /etc/audit/rules.d/30-ospp-v42-remediation.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61253r921495_chk'
  tag severity: 'medium'
  tag gid: 'V-257518'
  tag rid: 'SV-257518r921497_rule'
  tag stig_id: 'CNTR-OS-000160'
  tag gtitle: 'SRG-APP-000091-CTR-000160'
  tag fix_id: 'F-61177r921496_fix'
  tag satisfies: ['SRG-APP-000091-CTR-000160', 'SRG-APP-000492-CTR-001220', 'SRG-APP-000493-CTR-001225', 'SRG-APP-000494-CTR-001230', 'SRG-APP-000500-CTR-001260', 'SRG-APP-000507-CTR-001295']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
