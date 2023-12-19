control 'SV-899' do
  title 'All interactive users must be assigned a home directory in the /etc/passwd file.'
  desc 'If users do not have a valid home directory, there is no place for the storage and control of files they own.'
  desc 'check', 'Check all user accounts home directory assignments.  If any user account does not have a home directory, this is a finding.'
  desc 'fix', 'Assign a home directory to any user without one.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-307r2_chk'
  tag severity: 'low'
  tag gid: 'V-899'
  tag rid: 'SV-899r2_rule'
  tag stig_id: 'GEN001440'
  tag gtitle: 'GEN001440'
  tag fix_id: 'F-1053r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
