control 'SV-207098' do
  title 'The BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.'
  desc 'Accepting route advertisements for Bogon prefixes can result in the local autonomous system (AS) becoming a transit for malicious traffic as it will in turn advertise these prefixes to neighbor autonomous systems.'
  desc 'check', 'Review the router configuration to verify that it will reject routes of any Bogon prefixes.

The prefix filter must be referenced inbound on the appropriate BGP neighbor statements.

If the router is not configured to reject inbound route advertisements for any Bogon prefixes, this is a finding.'
  desc 'fix', 'Ensure all eBGP routers are configured to reject inbound route advertisements for any Bogon prefixes.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7359r382139_chk'
  tag severity: 'medium'
  tag gid: 'V-207098'
  tag rid: 'SV-207098r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000002'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7359r382140_fix'
  tag 'documentable'
  tag legacy: ['V-78267', 'SV-92973']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
