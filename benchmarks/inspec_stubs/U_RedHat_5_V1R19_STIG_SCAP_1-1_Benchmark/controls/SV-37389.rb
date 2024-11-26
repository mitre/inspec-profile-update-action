control 'SV-37389' do
  title 'The .rhosts file must not be supported in PAM.'
  desc '.rhosts files are used to specify a list of hosts permitted remote access to a particular account without authenticating. The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'fix', 'Edit the file(s) in /etc/pam.d referencing the rhosts_auth module, and remove the references to the rhosts_auth module.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11989'
  tag rid: 'SV-37389r1_rule'
  tag stig_id: 'GEN002100'
  tag gtitle: 'GEN002100'
  tag fix_id: 'F-31319r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
