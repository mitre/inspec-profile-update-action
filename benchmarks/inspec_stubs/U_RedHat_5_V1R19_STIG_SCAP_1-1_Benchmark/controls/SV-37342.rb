control 'SV-37342' do
  title 'The /etc/securetty file must have mode 0600 or less permissive.'
  desc 'The securetty file contains the list of terminals permitting direct root logins.  It must be protected from unauthorized modification.'
  desc 'fix', 'Change the mode of the /etc/securetty file to 0600.

Procedure:
# chmod 0600 /etc/securetty'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-12040'
  tag rid: 'SV-37342r3_rule'
  tag stig_id: 'GEN000000-LNX00660'
  tag gtitle: 'GEN000000-LNX00660'
  tag fix_id: 'F-31277r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
