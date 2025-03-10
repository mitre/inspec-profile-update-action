control 'SV-207101' do
  title 'The BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).'
  desc 'Advertisement of routes by an autonomous system for networks that do not belong to any of its customers pulls traffic away from the authorized network. This causes a denial of service (DoS) on the network that allocated the block of addresses and may cause a DoS on the network that is inadvertently advertising it as the originator. It is also possible that a misconfigured or compromised router within the GIG IP core could redistribute IGP routes into BGP, thereby leaking internal routes.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify that there is a filter defined to only advertise routes for prefixes that belong to any customers or the local AS.

The prefix filter must be referenced outbound on the appropriate BGP neighbor statements.

If the router is not configured to reject outbound route advertisements that belong to any customers or the local AS, this is a finding.'
  desc 'fix', 'Configure all eBGP routers to filter outbound route advertisements for prefixes that are not allocated to or belong to any customer or the local AS.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7362r382148_chk'
  tag severity: 'medium'
  tag gid: 'V-207101'
  tag rid: 'SV-207101r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000005'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7362r382149_fix'
  tag 'documentable'
  tag legacy: ['SV-92979', 'V-78273']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
