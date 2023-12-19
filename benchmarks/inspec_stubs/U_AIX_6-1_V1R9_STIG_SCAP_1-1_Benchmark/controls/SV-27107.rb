control 'SV-27107' do
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication.  If the root user is configured without a password, the entire system may be compromised.  For user accounts not using password authentication, the account must be configured with a password lock value instead of a blank or null value.'
  desc 'fix', 'Remove or configure a password for any account with a blank password.  

# passwd <user id>
# smitty passwd

To remove an account with a blank password.
# smitty rmuser'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag severity: 'high'
  tag gid: 'V-770'
  tag rid: 'SV-27107r1_rule'
  tag stig_id: 'GEN000560'
  tag gtitle: 'GEN000560'
  tag fix_id: 'F-33344r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
