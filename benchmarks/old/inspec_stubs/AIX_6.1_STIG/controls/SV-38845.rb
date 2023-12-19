control 'SV-38845' do
  title 'The .rhosts file must not be supported in PAM.'
  desc 'The .rhosts files are used to specify a list of hosts permitted remote access to a particular account without authenticating.  The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'check', 'Check the PAM configuration for rhosts_auth. 

Procedure: 
# grep rhosts_auth /etc/pam.conf |grep -v \\#

If a rhosts_auth entry is found, this is a finding.'
  desc 'fix', 'Edit /etc/pam.conf and remove the reference(s) to the rhosts_auth module.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11989'
  tag rid: 'SV-38845r1_rule'
  tag stig_id: 'GEN002100'
  tag gtitle: 'GEN002100'
  tag fix_id: 'F-33100r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
