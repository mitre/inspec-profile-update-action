control 'SV-207148' do
  title 'The Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.'
  desc 'MSDP peering with customer network routers presents additional risks to the core, whether from a rogue or misconfigured MSDP-enabled router. MSDP password authentication is used to validate each segment sent on the TCP connection between MSDP peers, protecting the MSDP session against the threat of spoofed packets being injected into the TCP connection stream.'
  desc 'check', 'Review the router configuration to determine if received MSDP packets are authenticated.

If the router does not require MSDP authentication, this is a finding.'
  desc 'fix', 'Ensure all MSDP packets received by an MSDP router are authenticated.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7409r382427_chk'
  tag severity: 'medium'
  tag gid: 'V-207148'
  tag rid: 'SV-207148r604135_rule'
  tag stig_id: 'SRG-NET-000343-RTR-000002'
  tag gtitle: 'SRG-NET-000343'
  tag fix_id: 'F-7409r382428_fix'
  tag 'documentable'
  tag legacy: ['SV-93047', 'V-78341']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
