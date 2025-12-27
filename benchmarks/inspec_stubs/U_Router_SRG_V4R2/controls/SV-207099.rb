control 'SV-207099' do
  title 'The BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc 'Accepting route advertisements belonging to the local AS can result in traffic looping or being black holed, or at a minimum using a non-optimized path.'
  desc 'check', 'Review the router configuration to verify that it will reject routes belonging to the local AS.

The prefix filter must be referenced inbound on the appropriate BGP neighbor statements.

If the router is not configured to reject inbound route advertisements belonging to the local AS, this is a finding.'
  desc 'fix', 'Ensure all eBGP routers are configured to reject inbound route advertisements for any prefixes belonging to the local AS.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7360r382142_chk'
  tag severity: 'medium'
  tag gid: 'V-207099'
  tag rid: 'SV-207099r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000003'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7360r382143_fix'
  tag 'documentable'
  tag legacy: ['SV-92975', 'V-78269']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
