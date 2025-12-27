control 'SV-27184' do
  title 'All interactive users must be assigned a home directory in the /etc/passwd file.'
  desc 'If users do not have a valid home directory, there is no place for the storage and control of files they own.'
  desc 'fix', 'Assign a home directory to any user without one.'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-899'
  tag rid: 'SV-27184r1_rule'
  tag stig_id: 'GEN001440'
  tag gtitle: 'GEN001440'
  tag fix_id: 'F-1053r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
