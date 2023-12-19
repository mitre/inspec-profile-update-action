control 'SV-250721' do
  title 'The system must use templates to deploy VMs whenever possible.'
  desc 'By capturing a hardened base operating system image (with no applications installed) in a template, ensure all virtual machines are created with a known baseline level of security. Then use this template to create other, application-specific templates, or use the application template to deploy virtual machines. Manual installation of the OS and applications into a VM introduces the risk of misconfiguration due to human or process error.'
  desc 'check', 'Ask the SA if hardened, patched templates are used for VM creation, properly configured OS deployments, including applications both dependent and non-dependent on VM-specific configurations.

If hardened, patched templates are not used for VM creation, this is a finding.'
  desc 'fix', 'Hardened, patched templates must be used for VM creation, properly configured OS deployments and applications. Applications dependent on VM-specific information must also use hardened, patched templates.'
  impact 0.3
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54156r799638_chk'
  tag severity: 'low'
  tag gid: 'V-250721'
  tag rid: 'SV-250721r799639_rule'
  tag stig_id: 'ESXI5-VM-000050'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54110r799624_fix'
  tag 'documentable'
  tag legacy: ['V-39504', 'SV-51362']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
