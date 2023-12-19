control 'SV-218649' do
  title 'Samba must be configured to use encrypted passwords.'
  desc 'Samba must be configured to protect authenticators.  If Samba passwords are not encrypted for storage, plain-text user passwords may be read by those with access to the Samba password file.'
  desc 'check', %q(If the "samba-common" package is not installed, this is not applicable.

Check the encryption setting of Samba.

# grep -i 'encrypt passwords' /etc/samba/smb.conf
 
If the setting is not present, or not set to 'yes', this is a finding.)
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and change the "encrypt passwords" setting to "yes".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20124r556145_chk'
  tag severity: 'medium'
  tag gid: 'V-218649'
  tag rid: 'SV-218649r603259_rule'
  tag stig_id: 'GEN006230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20122r556146_fix'
  tag 'documentable'
  tag legacy: ['V-22500', 'SV-64041']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
