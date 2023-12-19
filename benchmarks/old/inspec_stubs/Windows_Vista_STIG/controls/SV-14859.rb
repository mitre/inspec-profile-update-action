control 'SV-14859' do
  title 'Users must be prevented from connecting using Terminal Services.'
  desc 'Allowing a Terminal Services session to a workstation enables another avenue of access that could be exploited.  The system must be configured to prevent users from connecting to a computer using Terminal Services.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Connections "Allow users to connect remotely using Terminal Services" to "Disabled.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14248'
  tag rid: 'SV-14859r2_rule'
  tag gtitle: 'TS/RDS - Remote User Connections'
  tag fix_id: 'F-53567r1_fix'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
