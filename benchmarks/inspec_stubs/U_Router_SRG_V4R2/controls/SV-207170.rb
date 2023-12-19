control 'SV-207170' do
  title 'The Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network routers presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled router. To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP routers must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

If the router is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Ensure the receive path or interface filter for all MSDP routers only accepts MSDP packets from known MSDP peers.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7431r382538_chk'
  tag severity: 'medium'
  tag gid: 'V-207170'
  tag rid: 'SV-207170r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000116'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-7431r382539_fix'
  tag 'documentable'
  tag legacy: ['SV-93045', 'V-78339']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
