control 'SV-39245' do
  title 'Samba must be configured to not allow guest access to shares.'
  desc 'Guest access to shares permits anonymous access and is not permitted.'
  desc 'check', "Check the encryption setting the Samba configuration.
# grep -i 'guest ok'  /usr/lib/smb.conf
If the setting exists and is set to yes, this is a finding."
  desc 'fix', 'Edit the smb.conf file and change the guest ok setting to no. 

# vi /usr/lib/smb.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38220r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22501'
  tag rid: 'SV-39245r1_rule'
  tag stig_id: 'GEN006235'
  tag gtitle: 'GEN006235'
  tag fix_id: 'F-33495r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
