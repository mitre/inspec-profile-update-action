control 'SV-29528' do
  title 'The system is not configured to force users to log off when their allowed logon hours expire.'
  desc 'This setting controls whether or not users are forced to log off when their allowed logon hours expire.  If logon hours are set for users, then this should be enforced.'
  desc 'fix', 'Configure the system to log off users when their allowed logon hours expire.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3380'
  tag rid: 'SV-29528r1_rule'
  tag gtitle: 'Force Logoff When Logon Hours Expire'
  tag fix_id: 'F-142r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
