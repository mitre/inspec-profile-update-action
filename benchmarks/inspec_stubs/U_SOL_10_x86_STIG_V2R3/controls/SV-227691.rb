control 'SV-227691' do
  title 'The .rhosts file must not be supported in PAM.'
  desc 'The .rhosts files are used to specify a list of hosts that are permitted remote access to a particular account without authenticating.  The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'check', 'Check the PAM configuration for rhosts_auth.

Procedure:
# grep rhosts_auth /etc/pam.conf

If a rhosts_auth entry is found that is not commented out, this is a finding.'
  desc 'fix', 'Edit /etc/pam.conf and remove the reference(s) to the rhosts_auth module.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29853r488654_chk'
  tag severity: 'medium'
  tag gid: 'V-227691'
  tag rid: 'SV-227691r603266_rule'
  tag stig_id: 'GEN002100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29841r488655_fix'
  tag 'documentable'
  tag legacy: ['V-11989', 'SV-40334']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
