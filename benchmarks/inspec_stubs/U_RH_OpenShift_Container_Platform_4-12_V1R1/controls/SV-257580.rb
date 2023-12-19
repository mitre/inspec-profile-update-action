control 'SV-257580' do
  title 'Red Hat Enterprise Linux CoreOS (RHCOS) must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'By generating audit logs for the loading and unloading of dynamic kernel modules, OpenShift enables administrators and security teams to track and investigate any unauthorized or suspicious changes to the kernel modules. These records serve as a vital source of information for detecting and responding to potential security breaches or unauthorized module manipulations.

Audit records play a crucial role in forensic analysis and investigation. In the event of a security incident or suspected compromise, audit logs for dynamic kernel module loading and unloading provide valuable information for understanding the sequence of events and identifying any unauthorized or malicious module manipulations.

Audit records for module loading and unloading can be used for system performance analysis and troubleshooting. By reviewing these records, administrators can identify any problematic or misbehaving modules that may affect system performance or stability. This helps in diagnosing and resolving issues related to kernel modules more effectively.'
  desc 'check', %q(Verify the audit rules capture loading and unloading of kernel modules by executing the following:
 
for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e module-load -e module-unload -e module-change /etc/audit/rules.d/* /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node.

-a always,exit -F arch=b32 -S init_module,finit_module -F key=module-load
-a always,exit -F arch=b64 -S init_module,finit_module -F key=module-load
-a always,exit -F arch=b32 -S delete_module -F key=module-unload
-a always,exit -F arch=b64 -S delete_module -F key=module-unload
-a always,exit -F arch=b32 -S delete_module -k module-change
-a always,exit -F arch=b64 -S delete_module -k module-change
-a always,exit -F arch=b32 -S finit_module -k module-change
-a always,exit -F arch=b64 -S finit_module -k module-change
-a always,exit -F arch=b32 -S init_module -k module-change
-a always,exit -F arch=b64 -S init_module -k module-change

If the above rules are not listed for each node, this is a finding.)
  desc 'fix', 'Apply the machine config for audit rules capture by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-kernel-modules-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,%23%23%20These%20rules%20watch%20for%20kernel%20module%20insertion.%20By%20monitoring%0A%23%23%20the%20syscall%2C%20we%20do%20not%20need%20any%20watches%20on%20programs.%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20init_module%2Cfinit_module%20-F%20key%3Dmodule-load%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20init_module%2Cfinit_module%20-F%20key%3Dmodule-load%0A-a%20always%2Cexit%20-F%20arch%3Db32%20-S%20delete_module%20-F%20key%3Dmodule-unload%0A-a%20always%2Cexit%20-F%20arch%3Db64%20-S%20delete_module%20-F%20key%3Dmodule-unload%0A
        mode: 0644
        path: /etc/audit/rules.d/43-module-load.rules
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
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61315r921681_chk'
  tag severity: 'medium'
  tag gid: 'V-257580'
  tag rid: 'SV-257580r921683_rule'
  tag stig_id: 'CNTR-OS-000980'
  tag gtitle: 'SRG-APP-000504-CTR-001280'
  tag fix_id: 'F-61239r921682_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
