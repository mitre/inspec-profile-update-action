control 'SV-104467' do
  title 'System administrators must use templates to deploy virtual machines whenever possible.'
  desc 'By capturing a hardened base operating system image (with no applications installed) in a template, ensure all virtual machines are created with a known baseline level of security. Then use this template to create other, application-specific templates, or use the application template to deploy virtual machines. Manual installation of the OS and applications into a VM introduces the risk of misconfiguration due to human or process error.'
  desc 'check', 'Ask the SA if hardened, patched templates are used for VM creation, properly configured OS deployments, including applications both dependent and non-dependent on VM-specific configurations.

If hardened, patched templates are not used for VM creation, this is a finding.'
  desc 'fix', 'Create hardened virtual machine templates to use for OS deployments.'
  impact 0.3
  ref 'DPMS Target VMWare Virtual Machine 6.5'
  tag check_id: 'C-93827r1_chk'
  tag severity: 'low'
  tag gid: 'V-94637'
  tag rid: 'SV-104467r1_rule'
  tag stig_id: 'VMCH-65-000042'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-100755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
