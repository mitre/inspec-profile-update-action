control 'SV-26831' do
  title 'Samba must be configured to use encrypted passwords.'
  desc 'Samba must be configured to protect authenticators.  If Samba passwords are not encrypted for storage, plain-text user passwords may be read by those with access to the Samba password file.'
  desc 'check', "Check the encryption setting of the Samba configuration. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:

# grep -i 'encrypt passwords' /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the setting is not present, or not set to yes, this is a finding."
  desc 'fix', 'Edit the smb.conf file and change the encrypt passwords setting to yes.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27814r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22500'
  tag rid: 'SV-26831r2_rule'
  tag stig_id: 'GEN006230'
  tag gtitle: 'GEN006230'
  tag fix_id: 'F-24074r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
