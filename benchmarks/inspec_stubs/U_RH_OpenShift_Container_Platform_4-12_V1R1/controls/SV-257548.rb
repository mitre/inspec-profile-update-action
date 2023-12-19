control 'SV-257548' do
  title 'OpenShift must prevent unauthorized and unintended information transfer via shared system resources and enable page poisoning.'
  desc 'Enabling page poisoning in OpenShift improves memory safety, mitigates memory corruption vulnerabilities, aids in fault isolation, assists with debugging. It enhances the overall security and stability of the platform, reducing the risk of memory-related exploits and improving the resilience of applications running on OpenShift.'
  desc 'check', %q(Check the current CoreOS boot loader configuration has page poisoning enabled by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME ";  grep page_poison /boot/loader/entries/*.conf|| echo "not found"' 2>/dev/null; done

If "page_poison" is not set to "1" or returns "not found", this is a finding.)
  desc 'fix', 'Apply the machine config to enable page poisoning by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 05-kernelarg-page-poison-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
  kernelArguments:
  - page_poison=1
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61283r921585_chk'
  tag severity: 'medium'
  tag gid: 'V-257548'
  tag rid: 'SV-257548r921587_rule'
  tag stig_id: 'CNTR-OS-000560'
  tag gtitle: 'SRG-APP-000243-CTR-000600'
  tag fix_id: 'F-61207r921586_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
