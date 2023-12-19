control 'SV-227027' do
  title 'Samba must be configured to use an authentication mechanism other than "share."'
  desc 'Samba share authentication does not provide for individual user identification and must not be used.'
  desc 'check', 'Check the security mode of the Samba configuration. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:
# grep -i security /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf
If the security mode is share, this is a finding.'
  desc 'fix', 'Edit the smb.conf file and change the security setting to user or another valid setting other than share.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29189r485435_chk'
  tag severity: 'medium'
  tag gid: 'V-227027'
  tag rid: 'SV-227027r603265_rule'
  tag stig_id: 'GEN006225'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29177r485436_fix'
  tag 'documentable'
  tag legacy: ['SV-40295', 'V-22499']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
