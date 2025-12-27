control 'SV-214166' do
  title 'Signature generation using the KSK must be done off-line, using the KSK-private stored off-line.'
  desc 'Infoblox systems when deployed in a Grid configuration store DNSSEC keys on the designated Grid Master system. As the central point of administration, the Grid Master should be configured for administration of the DNS, DHCP, and IP Address Management (IPAM) system. No clients should be configured to utilize the Grid Master or backup Candidate systems for protocol transactions.

An alternative solution is through deployment of a Hardware Security Module (HSM), which provides hardware encrypted storage of key data.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

By default KSK private keys are stored on the Grid Master. The Grid Master will by default enable the DNS service when DNSSEC is enabled for internal processing. No clients are permitted to utilize the Grid Master DNS service.

Navigate to Data Management >> DNS >> Zones.

Review each zone by selecting the zone and clicking edit, and selecting the "Name Servers" tab.

If the Grid Master is a listed name server and not marked "Stealth", this is a finding.

If a HSM is utilized, no further checks are necessary.

When complete, click "Cancel" to exit the "Properties" screen.'
  desc 'fix', 'If the Grid Master stores the keys, review each DNS zone name server configuration to ensure the Grid Master does not appear as a name server (NS record); when configured in this manner the Grid Master is configured as a stealth name server and does not service client requests.

Refer to the Infoblox STIG Overview document for additional information on HSM usage.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15381r295764_chk'
  tag severity: 'medium'
  tag gid: 'V-214166'
  tag rid: 'SV-214166r612370_rule'
  tag stig_id: 'IDNS-7X-000190'
  tag gtitle: 'SRG-APP-000176-DNS-000096'
  tag fix_id: 'F-15379r295765_fix'
  tag 'documentable'
  tag legacy: ['V-68527', 'SV-83017']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
