control 'SV-215433' do
  title 'The .rhosts file must not be supported in AIX PAM.'
  desc '.rhosts files are used to specify a list of hosts permitted remote access to a particular account without authenticating. The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'check', 'Check the PAM configuration for "rhosts_auth" using command: 
# grep rhosts_auth /etc/pam.conf |grep -v \\# 

If a "rhosts_auth" entry is found, this is a finding.'
  desc 'fix', 'Edit "/etc/pam.conf" and remove the reference(s) to the "rhosts_auth" module.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16631r294750_chk'
  tag severity: 'medium'
  tag gid: 'V-215433'
  tag rid: 'SV-215433r877377_rule'
  tag stig_id: 'AIX7-00-003139'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16629r294751_fix'
  tag 'documentable'
  tag legacy: ['V-91741', 'SV-101839']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
