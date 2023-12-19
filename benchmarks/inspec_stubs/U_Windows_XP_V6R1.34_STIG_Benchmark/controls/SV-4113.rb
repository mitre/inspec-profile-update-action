control 'SV-4113' do
  title 'The system is configured for a greater keep-alive time than recommended.'
  desc 'Controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds” to “300000 or 5 minutes (recommended)” or less.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-4113'
  tag rid: 'SV-4113r1_rule'
  tag gtitle: 'TCP Connection Keep-Alive Time'
  tag fix_id: 'F-28004r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
