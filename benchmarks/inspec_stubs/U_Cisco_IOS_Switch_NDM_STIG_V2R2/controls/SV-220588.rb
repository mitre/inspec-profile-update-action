control 'SV-220588' do
  title 'The Cisco switch must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.'
  desc 'check', 'Review the Cisco switch configuration to verify that SSH is configured to use FIPS-140-2 compliant HMACs as shown in the example below:

ip ssh version 2
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr 

Note: An SSH configuration enables a server and client to authorize the negotiation of only algorithms that are configured from the allowed list. If a remote party tries to negotiate using an algorithm that is not part of the allowed list, the request is rejected and the session is not established. 

If the switch is not configured to implement replay-resistant authentication mechanisms for network access to privileged accounts, this is a finding.'
  desc 'fix', 'Configure SSH to use FIPS-140-2 compliant HMACs as shown in the example below:

SW1(config)#ip ssh version 2
SW1(config)#ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr 

Note: An SSH configuration enables a server and client to authorize the negotiation of only algorithms that are configured from the allowed list. If a user tries to negotiate using an algorithm that is not part of the allowed list, the request is rejected and the session is not established.'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22303r507810_chk'
  tag severity: 'medium'
  tag gid: 'V-220588'
  tag rid: 'SV-220588r521267_rule'
  tag stig_id: 'CISC-ND-000530'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-22292r507811_fix'
  tag 'documentable'
  tag legacy: ['SV-110405', 'V-101301']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
