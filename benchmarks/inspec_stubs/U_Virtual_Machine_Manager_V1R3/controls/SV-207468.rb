control 'SV-207468' do
  title 'The VMM must prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software or guest VMs, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the VMM. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

VMM functionality will vary, and while users are not permitted to install unapproved software or guest VMs, there may be instances when the organization allows the user to install approved software packages such as from an approved software repository. 

The VMM or software configuration management utility must enforce control of software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.'
  desc 'check', 'Verify the VMM prohibits user installation of software or guest VMs without explicit privileged status.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prohibit user installation of software or guest VMs without explicit privileged status.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7725r365808_chk'
  tag severity: 'medium'
  tag gid: 'V-207468'
  tag rid: 'SV-207468r854641_rule'
  tag stig_id: 'SRG-OS-000362-VMM-001390'
  tag gtitle: 'SRG-OS-000362'
  tag fix_id: 'F-7725r365809_fix'
  tag 'documentable'
  tag legacy: ['SV-71397', 'V-57137']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
