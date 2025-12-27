control 'SV-257550' do
  title 'OpenShift must enable poisoning of SLUB/SLAB objects.'
  desc 'By enabling poisoning of SLUB/SLAB objects, OpenShift can detect and identify use-after-free scenarios more effectively. The poisoned objects are marked as invalid or inaccessible, causing crashes or triggering alerts when an application attempts to access them. This helps identify and mitigate potential security vulnerabilities before they can be exploited.'
  desc 'check', %q(Verify that Red Hat Enterprise Linux CoreOS (RHCOS) is configured to enable poisoning of SLUB/SLAB objects to mitigate use-after-free vulnerabilities by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME ";  grep slub_debug /boot/loader/entries/*.conf ' 2>/dev/null; done

If "slub_debug" is not set to "P" or is missing, this is a finding.)
  desc 'fix', 'Apply the machine config to enable poisoning of SLUB/SLAB objects by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 05-kernelarg-slub-debug-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
  kernelArguments:
  - slub_debug=P
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61285r921591_chk'
  tag severity: 'medium'
  tag gid: 'V-257550'
  tag rid: 'SV-257550r921593_rule'
  tag stig_id: 'CNTR-OS-000580'
  tag gtitle: 'SRG-APP-000243-CTR-000600'
  tag fix_id: 'F-61209r921592_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
