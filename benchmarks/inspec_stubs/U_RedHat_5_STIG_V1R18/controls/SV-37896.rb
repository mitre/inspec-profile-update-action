control 'SV-37896' do
  title 'Samba must be configured to not allow guest access to shares.'
  desc 'Guest access to shares permits anonymous access and is not permitted.'
  desc 'check', "Check the access to shares for Samba.
# grep -i 'guest ok' /etc/samba/smb.conf 
If the setting exists and is set to 'yes', this is a finding."
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and change the "guest ok" setting to "no".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37122r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22501'
  tag rid: 'SV-37896r1_rule'
  tag stig_id: 'GEN006235'
  tag gtitle: 'GEN006235'
  tag fix_id: 'F-32390r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
