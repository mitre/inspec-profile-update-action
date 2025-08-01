control 'SV-214218' do
  title 'The private keys corresponding to both the ZSK and the KSK must not be kept on the DNSSEC-aware primary authoritative name server when the name server does not support dynamic updates.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored off-line (with respect to the Internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) has to have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRsets. The private key corresponding to the key-signing key (KSK-private) can still be kept off-line.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

By default KSK and ZSK private keys are stored on the Grid Master within the Infoblox database. No clients should be permitted to utilize the Grid Master DNS service.

Navigate to Data Management >> DNS >> Zones

Review each zone by selecting the zone and clicking "Edit", and selecting the "Name Servers" tab.

If the Grid Master is a listed name server and not marked "Stealth", this is a finding.

If a Hardware Security Module (HSM) is configured, KSK and ZSK private keys are encrypted and stored on the HSM, this is not a finding.'
  desc 'fix', 'For each zone that is not in compliance reconfigure the "Name Servers" tab and modify the Grid Master by selecting "Stealth".

When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15433r295917_chk'
  tag severity: 'medium'
  tag gid: 'V-214218'
  tag rid: 'SV-214218r612370_rule'
  tag stig_id: 'IDNS-7X-000920'
  tag gtitle: 'SRG-APP-000516-DNS-000112'
  tag fix_id: 'F-15431r295918_fix'
  tag 'documentable'
  tag legacy: ['SV-83125', 'V-68635']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
