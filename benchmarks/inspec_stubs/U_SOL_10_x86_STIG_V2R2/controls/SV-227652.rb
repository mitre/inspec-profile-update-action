control 'SV-227652' do
  title 'All interactive users must be assigned a home directory in the /etc/passwd file.'
  desc 'If users do not have a valid home directory, there is no place for the storage and control of files they own.'
  desc 'check', 'Use pwck to verify home directory assignments are present.
# pwck
If any user is not assigned a home directory, this is a finding.'
  desc 'fix', 'Assign a home directory to any user without one.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29814r488516_chk'
  tag severity: 'low'
  tag gid: 'V-227652'
  tag rid: 'SV-227652r603266_rule'
  tag stig_id: 'GEN001440'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29802r488517_fix'
  tag 'documentable'
  tag legacy: ['V-899', 'SV-27184']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
