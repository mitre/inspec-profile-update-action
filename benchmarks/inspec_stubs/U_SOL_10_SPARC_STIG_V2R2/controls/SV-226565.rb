control 'SV-226565' do
  title 'The .rhosts file must not be supported in PAM.'
  desc 'The .rhosts files are used to specify a list of hosts that are permitted remote access to a particular account without authenticating.  The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'check', 'Check the PAM configuration for rhosts_auth.

Procedure:
# grep rhosts_auth /etc/pam.conf

If a rhosts_auth entry is found that is not commented out, this is a finding.'
  desc 'fix', 'Edit /etc/pam.conf and remove the reference(s) to the rhosts_auth module.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28726r483104_chk'
  tag severity: 'medium'
  tag gid: 'V-226565'
  tag rid: 'SV-226565r603265_rule'
  tag stig_id: 'GEN002100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28714r483105_fix'
  tag 'documentable'
  tag legacy: ['V-11989', 'SV-40334']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
