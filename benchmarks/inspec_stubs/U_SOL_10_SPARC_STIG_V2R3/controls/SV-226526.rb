control 'SV-226526' do
  title 'All interactive users must be assigned a home directory in the /etc/passwd file.'
  desc 'If users do not have a valid home directory, there is no place for the storage and control of files they own.'
  desc 'check', 'Use pwck to verify home directory assignments are present.
# pwck
If any user is not assigned a home directory, this is a finding.'
  desc 'fix', 'Assign a home directory to any user without one.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28687r482966_chk'
  tag severity: 'low'
  tag gid: 'V-226526'
  tag rid: 'SV-226526r603265_rule'
  tag stig_id: 'GEN001440'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28675r482967_fix'
  tag 'documentable'
  tag legacy: ['V-899', 'SV-27184']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
