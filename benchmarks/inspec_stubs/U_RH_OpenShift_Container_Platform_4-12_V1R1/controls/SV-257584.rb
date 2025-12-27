control 'SV-257584' do
  title 'Red Hat Enterprise Linux CoreOS (RHCOS) must disable USB Storage kernel module.'
  desc 'Disabling the USB Storage kernel module helps protect against potential data exfiltration or unauthorized access to sensitive data. USB storage devices can be used to transfer data in and out of the system, which poses a risk if unauthorized or untrusted devices are connected. By disabling the USB Storage kernel module, OpenShift can prevent the use of USB storage devices and reduce the risk of data breaches or unauthorized data transfers.

USB storage devices can potentially introduce malware or malicious code into the system. Disabling the USB Storage kernel module helps mitigate the risk of malware infections or the introduction of malicious software from external storage devices. It prevents unauthorized execution of code from USB storage devices, reducing the attack surface and protecting the system from potential security threats.

Disabling USB storage prevents unauthorized data transfers to and from the system. This helps enforce data loss prevention (DLP) policies and mitigates the risk of sensitive or confidential data being copied or stolen using USB storage devices. It adds an additional layer of control to protect against data leakage or unauthorized data movement.'
  desc 'check', %q(Verify the operating system disables the ability to load the USB Storage kernel module by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true"' 2>/dev/null; done

install usb-storage /bin/true

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.)
  desc 'fix', 'Apply the machine config to disable USB Storage to load USB Storage kernel module by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 80-kernmod-usb-storage-disable-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,install%20usb-storage%20/bin/true%0A
        mode: 0644
        path: /etc/modprobe.d/75-kernel_module_usb-storage_disabled.conf
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61319r921693_chk'
  tag severity: 'medium'
  tag gid: 'V-257584'
  tag rid: 'SV-257584r921695_rule'
  tag stig_id: 'CNTR-OS-001020'
  tag gtitle: 'SRG-APP-000141-CTR-000315'
  tag fix_id: 'F-61243r921694_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
