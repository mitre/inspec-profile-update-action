control 'SV-257569' do
  title 'Red Hat Enterprise Linux CoreOS (RHCOS) must implement ASLR (Address Space Layout Randomization) from unauthorized code execution.'
  desc 'ASLR is a security technique that randomizes the memory layout of processes, making it more difficult for attackers to predict the location of system components and exploit memory-based vulnerabilities. By implementing ASLR, OpenShift reduces the effectiveness of common attacks such as buffer overflow, return-oriented programming (ROP), and other memory corruption exploits.

ASLR enhances the resilience of the OpenShift platform by introducing randomness into the memory layout. This randomization makes it harder for attackers to exploit vulnerabilities and launch successful attacks. Even if a vulnerability exists in the system, the randomized memory layout introduced by ASLR reduces the chances of the attacker being able to reliably exploit it, increasing the overall security of the platform.

ASLR is particularly effective in mitigating remote code execution attacks. By randomizing the memory layout, ASLR prevents attackers from precisely predicting the memory addresses needed to execute malicious code. This makes it significantly more challenging for attackers to successfully exploit vulnerabilities and execute arbitrary code on the system.

Protection of Shared Libraries: ASLR also protects shared libraries used by applications running on OpenShift. By randomizing the base addresses of shared libraries, ASLR makes it harder for attackers to leverage vulnerabilities in shared libraries to compromise applications or gain unauthorized access to the system. It adds an extra layer of protection to prevent attacks targeting shared library vulnerabilities.'
  desc 'check', %q(Verify Red Hat Enterprise Linux CoreOS (RHCOS) implements ASLR by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; sysctl kernel.randomize_va_space
' 2>/dev/null; done

If "kernel.randomize_va_space" is not set to "2", this is a finding.)
  desc 'fix', 'Apply the machine config to implement ASLR by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-sysctl-kernel-randomize-va-space-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,kernel.randomize_va_space%3D2%0A
        mode: 0644
        path: /etc/sysctl.d/75-sysctl_kernel_randomize_va_space.conf
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61304r921648_chk'
  tag severity: 'medium'
  tag gid: 'V-257569'
  tag rid: 'SV-257569r921650_rule'
  tag stig_id: 'CNTR-OS-000870'
  tag gtitle: 'SRG-APP-000450-CTR-001105'
  tag fix_id: 'F-61228r921649_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
