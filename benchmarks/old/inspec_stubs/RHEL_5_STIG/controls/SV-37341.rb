control 'SV-37341' do
  title 'The /etc/securetty file must be owned by root.'
  desc 'The securetty file contains the list of terminals permitting direct root logins.  It must be protected from unauthorized modification.'
  desc 'fix', 'Change the owner of the /etc/securetty file to root.

Procedure:
# chown root /etc/securetty'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-12039'
  tag rid: 'SV-37341r1_rule'
  tag stig_id: 'GEN000000-LNX00640'
  tag gtitle: 'GEN000000-LNX00640'
  tag fix_id: 'F-11296r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
