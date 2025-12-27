control 'SV-257549' do
  title 'OpenShift must disable virtual syscalls.'
  desc 'Virtual syscalls are a mechanism that allows user-space programs to make privileged system calls without transitioning to kernel mode. However, this feature can introduce additional security risks. Disabling virtual syscalls helps to mitigate potential vulnerabilities associated with this mechanism. By reducing the attack surface and limiting the ways in which user-space programs can interact with the kernel, OpenShift can enhance the overall security posture of the platform.'
  desc 'check', %q(Check the current CoreOS boot loader configuration has virtual syscalls disabled by executing the following:

 for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME ";  grep vsyscall=none boot/loader/entries/*.conf || echo "not found"' 2>/dev/null; done

If "vsyscall" is not set to "none" or returns "not found", this is a finding.)
  desc 'fix', 'Apply the machine config to disable virtual syscalls by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 05-kernelarg-vsyscall-none-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
  kernelArguments:
  - vsyscall=none
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61284r921588_chk'
  tag severity: 'medium'
  tag gid: 'V-257549'
  tag rid: 'SV-257549r921590_rule'
  tag stig_id: 'CNTR-OS-000570'
  tag gtitle: 'SRG-APP-000243-CTR-000600'
  tag fix_id: 'F-61208r921589_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
