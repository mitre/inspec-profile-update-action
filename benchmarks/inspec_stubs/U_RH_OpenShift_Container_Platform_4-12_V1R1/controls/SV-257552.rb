control 'SV-257552' do
  title 'OpenShift must restrict access to the kernel buffer.'
  desc 'Restricting access to the kernel buffer in OpenShift is crucial for preventing unauthorized access, protecting system stability, mitigating kernel-level attacks, preventing information leakage, and adhering to the principle of least privilege. It enhances the security posture of the platform and helps maintain the confidentiality, integrity, and availability of critical system resources.'
  desc 'check', %q(Verify the Red Hat Enterprise Linux CoreOS (RHCOS) is configured to restrict access to the kernel message buffer.

Check the status of the kernel.dmesg_restrict kernel parameter by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; sysctl kernel.dmesg_restrict' 2>/dev/null; done

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Apply the machine config to restrict access to the kernel message buffer by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-sysctl-kernel-dmesg-restrict-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,kernel.dmesg_restrict%3D1%0A
        mode: 0644
        path: /etc/sysctl.d/75-sysctl_kernel_dmesg_restrict.conf
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61287r921597_chk'
  tag severity: 'medium'
  tag gid: 'V-257552'
  tag rid: 'SV-257552r921599_rule'
  tag stig_id: 'CNTR-OS-000600'
  tag gtitle: 'SRG-APP-000243-CTR-000600'
  tag fix_id: 'F-61211r921598_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
