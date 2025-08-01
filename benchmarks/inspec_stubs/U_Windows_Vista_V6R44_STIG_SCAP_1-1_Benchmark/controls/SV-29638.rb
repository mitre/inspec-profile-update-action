control 'SV-29638' do
  title 'Time before bad-logon counter is reset does not meet minimum requirements.'
  desc 'This parameter specifies the amount of time that must pass between two successive login attempts to ensure that a lockout will occur.  The smaller this value is, the less effective the account lockout feature will be in protecting the local system.'
  desc 'fix', 'Configure the system to have the lockout counter reset itself after a minimum of 60 minutes.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1098'
  tag rid: 'SV-29638r1_rule'
  tag gtitle: 'Bad Logon Counter Reset'
  tag fix_id: 'F-6570r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
