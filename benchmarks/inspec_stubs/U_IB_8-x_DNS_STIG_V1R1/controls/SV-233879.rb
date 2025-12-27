control 'SV-233879' do
  title 'The private keys corresponding to both the Zone Signing Key (ZSK) and the Key Signing Key (KSK) must not be kept on the DNSSEC-aware primary authoritative name server when the name server does not support dynamic updates.'
  desc 'The private keys in the KSK and ZSK key pairs must be protected from unauthorized access. If possible, the private keys should be stored offline (with respect to the internet-facing, DNSSEC-aware name server) in a physically secure, non-network-accessible machine along with the zone file master copy. 

This strategy is not feasible in situations in which the DNSSEC-aware name server has to support dynamic updates. To support dynamic update transactions, the DNSSEC-aware name server (which usually is a primary authoritative name server) must have both the zone file master copy and the private key corresponding to the zone-signing key (ZSK-private) online to immediately update the signatures for the updated RRSets. The private key corresponding to the key-signing key (KSK-private) can still be kept offline.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

By default, KSK and ZSK private keys are stored on the Grid Master within the Infoblox database. No clients should be permitted to use the Grid Master DNS service.  

1. Navigate to Data Management >> DNS >> Zones.  
2. Review each zone by selecting the zone and clicking "Edit" and selecting the "Name Servers" tab. 

If the Grid Master is a listed name server and not marked "Stealth", this is a finding.

If a Hardware Security Module (HSM) is configured, KSK and ZSK private keys are encrypted and stored on the HSM, this is not a finding.'
  desc 'fix', 'For each zone that is not in compliance:  

1. Navigate to Data Management >> DNS >> Zones.
2. Select and edit the zone. 
3. Select the "Name Servers" tab and modify the Grid Master by selecting "Stealth". 
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
5. Perform a service restart if necessary.'
  impact 0.7
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37064r611157_chk'
  tag severity: 'high'
  tag gid: 'V-233879'
  tag rid: 'SV-233879r621666_rule'
  tag stig_id: 'IDNS-8X-400021'
  tag gtitle: 'SRG-APP-000516-DNS-000112'
  tag fix_id: 'F-37029r611158_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
