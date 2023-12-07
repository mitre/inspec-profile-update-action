control 'SV-4117' do
  title 'The system is configured to allow SYN attacks.'
  desc 'Adjusts retransmission of TCP SYN-ACKs. When enabled, connection responses time out more quickly in the event of a SYN DoS attack.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (SynAttackProtect) Syn attack protection level (protects against DoS)” to “Connections time out sooner if a SYN attack is detected”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-4117'
  tag rid: 'SV-4117r1_rule'
  tag gtitle: 'SYN Attack Protection'
  tag fix_id: 'F-5725r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
