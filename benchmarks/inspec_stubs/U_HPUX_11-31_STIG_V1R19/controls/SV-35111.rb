control 'SV-35111' do
  title 'Samba must be configured to use encrypted passwords.'
  desc 'Samba must be configured to protect authenticators.  If Samba passwords are not encrypted for storage, plain-text user passwords may be read by those with access to the Samba password file.'
  desc 'check', %q(Check the encryption setting in the Samba configuration file.

# cat /etc/opt/samba/smb.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i "^encrypt passwords = yes"

If the encrypt passwords setting is not set to "yes", this is a finding.)
  desc 'fix', 'Edit the /etc/opt/samba/smb.conf file and change the encrypt passwords setting to yes, for example:

encrypt passwords = yes'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36706r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22500'
  tag rid: 'SV-35111r1_rule'
  tag stig_id: 'GEN006230'
  tag gtitle: 'GEN006230'
  tag fix_id: 'F-32083r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
