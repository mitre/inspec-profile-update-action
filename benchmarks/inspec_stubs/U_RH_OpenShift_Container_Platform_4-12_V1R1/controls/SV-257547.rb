control 'SV-257547' do
  title 'OpenShift runtime must isolate security functions from nonsecurity functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.
 
Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in several ways, including through the provision of security kernels via processor rings or processor modes. For nonkernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions using access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', %q(Verify the Red Hat Enterprise Linux CoreOS (RHCOS) verifies correct operation of all security functions by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; getenforce' 2>/dev/null; done

If "SELinux" is not active and not in "Enforcing" mode, this is a finding.)
  desc 'fix', 'Apply the machine config by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 05-kernelarg-selinux-enforcing-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
  kernelArguments:
    - enforcing=1
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61282r921582_chk'
  tag severity: 'medium'
  tag gid: 'V-257547'
  tag rid: 'SV-257547r921584_rule'
  tag stig_id: 'CNTR-OS-000540'
  tag gtitle: 'SRG-APP-000233-CTR-000585'
  tag fix_id: 'F-61206r921583_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
