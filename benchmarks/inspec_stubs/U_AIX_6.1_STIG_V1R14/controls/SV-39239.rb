control 'SV-39239' do
  title 'Samba must be configured to use an authentication mechanism other than share.'
  desc 'Samba share authentication does not provide for individual user identification and must not be used.'
  desc 'check', 'Check the security mode of the Samba configuration.
# grep -i security /usr/lib/smb.conf
If the security mode is share, this is a finding.'
  desc 'fix', 'Edit the /usr/lib/smb.conf file and change the security setting to user or another valid setting other than share.

# vi /usr/lib/smb.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38214r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22499'
  tag rid: 'SV-39239r1_rule'
  tag stig_id: 'GEN006225'
  tag gtitle: 'GEN006225'
  tag fix_id: 'F-33490r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
