control 'SV-14864' do
  title 'Restrict unauthenticated RPC clients.'
  desc 'This check verifies that the system is configured to restrict unauthenticated RPC clients from connecting to the RPC server.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call “Restrictions for Unauthenticated RPC clients” to “Enabled” and “Authenticated”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-14253'
  tag rid: 'SV-14864r1_rule'
  tag gtitle: 'RPC - Unauthenticated RPC Clients'
  tag fix_id: 'F-13578r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
