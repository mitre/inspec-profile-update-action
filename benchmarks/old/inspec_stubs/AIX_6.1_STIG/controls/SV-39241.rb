control 'SV-39241' do
  title 'Samba must be configured to use encrypted passwords.'
  desc 'Samba must be configured to protect authenticators.  If Samba passwords are not encrypted for storage, plain-text user passwords may be read by those with access to the Samba password file.'
  desc 'check', "Check the encryption setting the Samba configuration.

# grep -i 'encrypt passwords'  /usr/lib/smb.conf
If the setting is not present, or not set to yes, this is a finding."
  desc 'fix', 'Edit the smb.conf file and change the encrypt passwords setting to yes. 

# vi /usr/lib/smb.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38215r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22500'
  tag rid: 'SV-39241r1_rule'
  tag stig_id: 'GEN006230'
  tag gtitle: 'GEN006230'
  tag fix_id: 'F-33491r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
