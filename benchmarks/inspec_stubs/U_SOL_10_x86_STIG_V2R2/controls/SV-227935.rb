control 'SV-227935' do
  title 'Samba must be configured to use encrypted passwords.'
  desc 'Samba must be configured to protect authenticators.  If Samba passwords are not encrypted for storage, plain-text user passwords may be read by those with access to the Samba password file.'
  desc 'check', "Check the encryption setting of the Samba configuration.

Procedure:
# grep -i 'encrypt passwords' /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf
If the setting is not present, or not set to yes, this is a finding."
  desc 'fix', 'Edit the smb.conf file and change the encrypt passwords setting to yes.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30097r490225_chk'
  tag severity: 'medium'
  tag gid: 'V-227935'
  tag rid: 'SV-227935r603266_rule'
  tag stig_id: 'GEN006230'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30085r490226_fix'
  tag 'documentable'
  tag legacy: ['V-22500', 'SV-40296']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
