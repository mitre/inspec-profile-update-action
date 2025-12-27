control 'SV-242434' do
  title 'Kubernetes Kubelet must enable kernel protection.'
  desc 'System kernel is responsible for memory, disk, and task management. The kernel provides a gateway between the system hardware and software. Kubernetes requires kernel access to allocate resources to the Control Plane. Threat actors that penetrate the system kernel can inject malicious code or hijack the Kubernetes architecture. It is vital to implement protections through Kubernetes components to reduce the attack surface.'
  desc 'check', 'Change to the /etc/sysconfig/ directory on the Kubernetes Control Plane. Run the command:
grep -i protect-kernel-defaults kubelet  

If the setting "protect-kernel-defaults" is set to false or not set in the Kubernetes Kubelet, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Kubelet file in the /etc/sysconfig directory on the Kubernetes Control Plane. Set the argument "--protect-kernel-defaults" to "true". 

Reset Kubelet service using the following command:
service kubelet restart'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45709r863890_chk'
  tag severity: 'high'
  tag gid: 'V-242434'
  tag rid: 'SV-242434r879643_rule'
  tag stig_id: 'CNTR-K8-001620'
  tag gtitle: 'SRG-APP-000233-CTR-000585'
  tag fix_id: 'F-45667r863891_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
