control 'SV-46281' do
  title 'Samba must be configured to use encrypted passwords.'
  desc 'Samba must be configured to protect authenticators.  If Samba passwords are not encrypted for storage, plain-text user passwords may be read by those with access to the Samba password file.'
  desc 'check', %q(If the "samba-common" package is not installed, this is not applicable.

Check the encryption setting of Samba.
# grep -i 'encrypt passwords' /etc/samba/smb.conf 
If the setting is not present, or not set to 'yes', this is a finding.)
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and change the "encrypt passwords" setting to "yes".'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-37120r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22500'
  tag rid: 'SV-46281r1_rule'
  tag stig_id: 'GEN006230'
  tag gtitle: 'GEN006230'
  tag fix_id: 'F-32388r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
