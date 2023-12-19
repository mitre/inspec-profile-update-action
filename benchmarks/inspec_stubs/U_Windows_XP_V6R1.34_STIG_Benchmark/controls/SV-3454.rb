control 'SV-3454' do
  title 'Terminal Services is not configured with the client connection encryption set to the required level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information.  Selecting “High Level” will ensure encryption of Terminal Services sessions in both directions.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Encryption and Security “Set Client Connection Encryption Level” to “Enabled” and select “High Level” for the “Encryption Level”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3454'
  tag rid: 'SV-3454r2_rule'
  tag gtitle: 'TS/RDS - Set Encryption Level'
  tag fix_id: 'F-5923r2_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCT-1, ECCT-2'
end
