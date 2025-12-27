control 'SV-95649' do
  title 'AAA Services must be configured to use a unique shared secret for communication (i.e. RADIUS, TACACS+) with clients requesting authentication services.'
  desc 'Using standardized authentication protocols such as RADIUS, TACACS+, and Kerberos, an authentication server provides centralized and robust authentication services for the management of network components. An authentication server is very scalable as it supports many user accounts and authentication sessions with the network components.'
  desc 'check', 'If AAA Services are not used for 802.1x authentication or to authenticate privileged users for device management, this is not applicable.

Verify AAA Services are configured to use a unique shared secret with clients requesting authentication services. The shared secret is to be the same for communication between AAA Services and the client devices. All shared secrets must meet password complexity requirements.

If AAA Services are not configured to use a unique shared secret for communication with clients requesting authentication services, this is a finding.'
  desc 'fix', 'Configure AAA Services to use a unique shared secret for communication (i.e. RADIUS, TACACS+) with all clients requesting authentication services.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80939'
  tag rid: 'SV-95649r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000640'
  tag gtitle: 'SRG-APP-000516-AAA-000640'
  tag fix_id: 'F-87795r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
