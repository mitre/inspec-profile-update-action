control 'SV-203716' do
  title 'The operating system must prohibit user installation of system software without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Operating system functionality will vary, and while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages, such as from an approved software repository.

The operating system or software configuration management utility must enforce control of software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.'
  desc 'check', 'Verify the operating system prohibits user installation of system software without explicit privileged status. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit user installation of system software without explicit privileged status.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3841r375155_chk'
  tag severity: 'medium'
  tag gid: 'V-203716'
  tag rid: 'SV-203716r851785_rule'
  tag stig_id: 'SRG-OS-000362-GPOS-00149'
  tag gtitle: 'SRG-OS-000362'
  tag fix_id: 'F-3841r375156_fix'
  tag 'documentable'
  tag legacy: ['SV-71441', 'V-57181']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
