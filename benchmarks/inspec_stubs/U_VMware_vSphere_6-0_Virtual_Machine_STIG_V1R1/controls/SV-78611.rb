control 'SV-78611' do
  title 'The system must use templates to deploy VMs whenever possible.'
  desc 'By capturing a hardened base operating system image (with no applications installed) in a template, ensure all virtual machines are created with a known baseline level of security. Then use this template to create other, application-specific templates, or use the application template to deploy virtual machines. Manual installation of the OS and applications into a VM introduces the risk of misconfiguration due to human or process error.'
  desc 'check', 'Ask the SA if hardened, patched templates are used for VM creation, properly configured OS deployments, including applications both dependent and non-dependent on VM-specific configurations.

If hardened, patched templates are not used for VM creation, this is a finding.'
  desc 'fix', 'Create hardened virtual machine templates to use for OS deployments.'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64871r1_chk'
  tag severity: 'low'
  tag gid: 'V-64121'
  tag rid: 'SV-78611r1_rule'
  tag stig_id: 'VMCH-06-000043'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70049r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
