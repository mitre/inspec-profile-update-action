control 'SV-243465' do
  title 'If several PAWs are set up in virtual machines (VMs) on a host server, domain administrative accounts used to manage high-value IT resources must not have access to the VM host operating system (OS) (only domain administrative accounts designated to manage PAWs should be able to access the VM host OS).'
  desc 'The VM host OS should be protected from high-value IT resource administrators accidently or deliberately modifying the security settings of the host OS. Therefore, high-value IT resource administrators must not have the ability to perform maintenance functions on the VM host OS platform.'
  desc 'check', "Verify at least one group has been set up in Active Directory (usually Tier 0) for administrators responsible for maintaining VM host OSs (usually the same as the PAW workstation administrator's group).

Verify no administrator account or administrator account group has been assigned to both the group of VM host OS administrators and any group for administrators of high-value IT resources.

If separate VM host OS administrator groups and administrators of high-value IT resources have not been set up, this is a finding."
  desc 'fix', 'Configure the VM host OS so only domain administrative accounts designated to manage PAWs have administrative rights on the VM host OS.'
  impact 0.5
  ref 'DPMS Target Windows PAW'
  tag check_id: 'C-46740r722964_chk'
  tag severity: 'medium'
  tag gid: 'V-243465'
  tag rid: 'SV-243465r722970_rule'
  tag stig_id: 'WPAW-00-002600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46697r722965_fix'
  tag 'documentable'
  tag legacy: ['V-78187', 'SV-92893']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
