control 'SV-207108' do
  title 'The perimeter router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'Verify each router enforces approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.

If the router does not enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy, this is a finding.'
  desc 'fix', 'Configure the router to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7369r382169_chk'
  tag severity: 'medium'
  tag gid: 'V-207108'
  tag rid: 'SV-207108r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000002'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7369r382170_fix'
  tag 'documentable'
  tag legacy: ['V-55721', 'SV-69975']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
