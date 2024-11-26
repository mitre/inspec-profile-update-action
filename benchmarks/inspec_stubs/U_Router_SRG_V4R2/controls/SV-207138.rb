control 'SV-207138' do
  title 'The BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.'
  desc 'Outbound route advertisements belonging to the core can result in traffic either looping or being black holed, or at a minimum, using a non-optimized path.'
  desc 'check', 'Review the router configuration to verify that there is a filter defined to block route advertisements for prefixes that belong to the IP core. 

The prefix filter must be referenced outbound on the appropriate BGP neighbor statements.

If the router is not configured to reject outbound route advertisements that belong to the IP core, this is a finding.'
  desc 'fix', 'Configure all eBGP routers to filter outbound route advertisements belonging to the IP core.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7399r382352_chk'
  tag severity: 'medium'
  tag gid: 'V-207138'
  tag rid: 'SV-207138r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000006'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7399r382353_fix'
  tag 'documentable'
  tag legacy: ['V-78275', 'SV-92981']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
