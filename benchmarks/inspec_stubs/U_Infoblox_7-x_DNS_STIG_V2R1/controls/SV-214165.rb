control 'SV-214165' do
  title 'Only the private key corresponding to the ZSK alone must be kept on the name server that does support dynamic updates.'
  desc 'Infoblox systems when deployed in a Grid configuration store DNSSEC keys on the designated Grid Master system. As the central point of administration, the Grid Master should be configured for administration of the DNS, DHCP, and IP Address Management (IPAM) system. No clients should be configured to utilize the Grid Master or backup Candidate systems for protocol transactions.

An alternative solution is through deployment of a Hardware Security Module (HSM), which provides hardware encrypted storage of key data.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

By default ZSK private keys are stored encrypted within the Infoblox database on the Grid Master. The Grid Master will by default enable the DNS service when DNSSEC is enabled for internal processing. No clients should be permitted to utilize the Grid Master DNS service. 

Refer to the Infoblox STIG Overview document for additional information on HSM usage.

Navigate to Data Management >> DNS >> Zones.

Review each zone by selecting the zone and clicking "Edit", and selecting the "Name Servers" tab.

If the Grid Master is a listed name server and not marked "Stealth", this is a finding.

When complete, click "Cancel" to exit the "Properties" screen.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Zones.

Selecting the zone and click "Edit", then select the "Name Servers" tab.
Mark the Grid Master as "Stealth". If no other name servers are listed, one must be added before the configuration can be valid.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15380r295761_chk'
  tag severity: 'medium'
  tag gid: 'V-214165'
  tag rid: 'SV-214165r612370_rule'
  tag stig_id: 'IDNS-7X-000180'
  tag gtitle: 'SRG-APP-000176-DNS-000094'
  tag fix_id: 'F-15378r295762_fix'
  tag 'documentable'
  tag legacy: ['V-68525', 'SV-83015']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
