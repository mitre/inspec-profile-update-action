control 'SV-45169' do
  title 'The .rhosts file must not be supported in PAM.'
  desc '.rhosts files are used to specify a list of hosts permitted remote access to a particular account without authenticating. The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'check', 'Check the PAM configuration for rhosts_auth.

Example:
# grep rhosts_auth /etc/pam.d/*

If a rhosts_auth entry is found, this is a finding.'
  desc 'fix', 'Edit the file(s) in /etc/pam.d referencing the rhosts_auth module, and remove the references to the rhosts_auth module.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42514r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11989'
  tag rid: 'SV-45169r1_rule'
  tag stig_id: 'GEN002100'
  tag gtitle: 'GEN002100'
  tag fix_id: 'F-38567r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
