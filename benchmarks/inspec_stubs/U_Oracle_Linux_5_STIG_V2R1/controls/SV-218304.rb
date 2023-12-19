control 'SV-218304' do
  title 'All interactive users must be assigned a home directory in the /etc/passwd file.'
  desc 'If users do not have a valid home directory, there is no place for the storage and control of files they own.'
  desc 'check', 'Use pwck to verify home directory assignments are present.

# pwck

If any user is not assigned a home directory, this is a finding.'
  desc 'fix', 'Assign a home directory to any user without one.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19779r554249_chk'
  tag severity: 'low'
  tag gid: 'V-218304'
  tag rid: 'SV-218304r603259_rule'
  tag stig_id: 'GEN001440'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19777r554250_fix'
  tag 'documentable'
  tag legacy: ['V-899', 'SV-64577']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
