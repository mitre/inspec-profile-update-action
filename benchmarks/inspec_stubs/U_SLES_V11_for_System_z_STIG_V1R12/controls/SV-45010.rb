control 'SV-45010' do
  title 'All interactive users must be assigned a home directory in the /etc/passwd file.'
  desc 'If users do not have a valid home directory, there is no place for the storage and control of files they own.'
  desc 'check', 'Use pwck to verify home directory assignments are present.
# pwck
If any user is not assigned a home directory, this is a finding.'
  desc 'fix', 'Assign a home directory to any user without one.   This can be accomplished using ‘/sbin/yast2 users’ > Edit > Details to modify the home directory of an existing user.  Alternatively, the following command may be used:
# usermod -d </home/directory> <username>'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42409r1_chk'
  tag severity: 'low'
  tag gid: 'V-899'
  tag rid: 'SV-45010r1_rule'
  tag stig_id: 'GEN001440'
  tag gtitle: 'GEN001440'
  tag fix_id: 'F-38425r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
