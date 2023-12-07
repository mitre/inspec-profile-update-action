control 'SV-95647' do
  title 'AAA Services used to authenticate privileged users for device management must be configured to connect to the management network.'
  desc 'Using standardized authentication protocols such as RADIUS, TACACS+, and Kerberos, an authentication server provides centralized and robust authentication services for the management of network components. In order to control access to the servers as well as monitor traffic to them, the authentication servers should only be connected to the management network.'
  desc 'check', 'If AAA Services are not used for authentication of privileged users to AAA Services, this is not applicable.

Verify AAA Services are configured to connect to the management network. Confirm AAA Services are not dual-homed by physically inspecting the physical LAN connection.

If AAA Services are configured to connect to a non-management network, this is a finding.'
  desc 'fix', 'Configure AAA Services used to authenticate privileged users for device management to connect to the management network.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80937'
  tag rid: 'SV-95647r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000630'
  tag gtitle: 'SRG-APP-000516-AAA-000630'
  tag fix_id: 'F-87793r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
