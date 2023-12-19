control 'SV-35111' do
  title 'Samba must be configured to use encrypted passwords.'
  desc 'Samba must be configured to protect authenticators.  If Samba passwords are not encrypted for storage, plain-text user passwords may be read by those with access to the Samba password file.'
  desc 'fix', 'Edit the /etc/opt/samba/smb.conf file and change the encrypt passwords setting to yes, for example:

encrypt passwords = yes'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22500'
  tag rid: 'SV-35111r1_rule'
  tag stig_id: 'GEN006230'
  tag gtitle: 'GEN006230'
  tag fix_id: 'F-32083r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
