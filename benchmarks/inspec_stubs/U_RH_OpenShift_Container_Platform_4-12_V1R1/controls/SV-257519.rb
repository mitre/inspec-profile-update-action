control 'SV-257519' do
  title 'Red Hat Enterprise Linux CoreOS (RHCOS) must initiate session audits at system startup.'
  desc 'Initiating session audits at system startup allows for comprehensive monitoring of user activities and system events from the moment the system is powered on. Audit logs capture information about login attempts, commands executed, file access, and other system activities. By starting session audits at system startup, RHCOS ensures that all relevant events are recorded, providing a complete security monitoring solution. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

By initiating session audits at system startup, RHCOS enhances security monitoring, aids in timely incident detection and response, meets compliance requirements, facilitates forensic analysis, and promotes accountability and governance.'
  desc 'check', %q(Verify the RHCOS boot loader configuration has audit enabled, including backlog:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME ";  grep audit /boot/loader/entries/*.conf || echo "not found"' 2>/dev/null; done

If "audit" is not set to "1" or returns "not found", this is a finding.

If "audit_backlog" is not set to 8192 or returns "not found", this is a finding.)
  desc 'fix', 'Apply the machine config by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 05-kernelarg-audit-enabled-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
  kernelArguments:
  - audit=1
  - audit_backlog_limit=8192
" | oc create -f -
done'
  impact 0.7
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61254r921498_chk'
  tag severity: 'high'
  tag gid: 'V-257519'
  tag rid: 'SV-257519r921500_rule'
  tag stig_id: 'CNTR-OS-000170'
  tag gtitle: 'SRG-APP-000092-CTR-000165'
  tag fix_id: 'F-61178r921499_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
