control 'SV-26830' do
  title 'Samba must be configured to use an authentication mechanism other than share.'
  desc 'Samba share authentication does not provide for individual user identification and must not be used.'
  desc 'check', 'Check the security mode of the Samba configuration. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:

# grep -i security /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the security mode is share, this is a finding.'
  desc 'fix', 'Edit the smb.conf file and change the security setting to user or another valid setting other than share.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27812r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22499'
  tag rid: 'SV-26830r2_rule'
  tag stig_id: 'GEN006225'
  tag gtitle: 'GEN006225'
  tag fix_id: 'F-24073r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
