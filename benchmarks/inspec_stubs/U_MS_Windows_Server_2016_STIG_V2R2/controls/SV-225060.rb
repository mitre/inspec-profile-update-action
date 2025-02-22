control 'SV-225060' do
  title 'The default permissions of global system objects must be strengthened.'
  desc 'Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default Discretionary Access Control List (DACL) that specifies who can access the objects with what permissions. When this policy is enabled, the default DACL is stronger, allowing non-administrative users to read shared objects but not to modify shared objects they did not create.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\

Value Name: ProtectionMode

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26751r466082_chk'
  tag severity: 'low'
  tag gid: 'V-225060'
  tag rid: 'SV-225060r569186_rule'
  tag stig_id: 'WN16-SO-000450'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26739r466083_fix'
  tag 'documentable'
  tag legacy: ['SV-88369', 'V-73705']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
