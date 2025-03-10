control 'SV-233904' do
  title 'The Infoblox Grid Master must be configured as a stealth (hidden) domain name server in order to protect the Zone Signing Key (ZSK) residing on it.'
  desc 'Security-relevant information is any information within information systems that can potentially impact the operation of security functions or the provision of security services in a manner that could result in failure to enforce system security policies or maintain the isolation of code and data. 

Security-relevant information includes, for example, file permissions, cryptographic key management information, configuration parameters for security services, and access control lists. Secure, non-operable system states include the times in which information systems are not performing mission/business-related processing (e.g., the system is offline for maintenance, troubleshooting, bootup, and shutdown).

On Infoblox, Domain Name System Security Extension (DNSSEC) Zone Signing Keys (ZSKs) are stored on either a Hardware Security Module or the Infoblox Grid Master. By configuring the Grid Master as "stealth" to prevent client communications to the Infoblox Grid Master and ensuring  the Grid Master uses an encrypted management tunnel to update DNS members serving DNSSEC signed zones, the DNSSEC keys are protected.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

By default, Zone Signing Key (ZSK) private keys are stored encrypted within the Infoblox database on the Grid Master. The Grid Master will by default enable the DNS service when DNSSEC is enabled for internal processing. No clients should be permitted to use the Grid Master DNS service. Refer to the Infoblox STIG Overview document for additional information on HSM usage. 

1. Navigate to Data Management >> DNS >> Zones.  
2. Review each zone by selecting the zone, clicking "Edit", and selecting the "Name Servers" tab. 
3. When complete, click "Cancel" to exit the "Properties" screen.  

If the Grid Master is a listed name server and not marked "Stealth", this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones.  
2. Select the zone, click "Edit", and select the "Name Servers" tab. 
3. Mark the Grid Master as "Stealth". 
4. If no other name servers are listed, one must be added before the configuration can be valid. 
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  
6. Perform a service restart if necessary.'
  impact 0.7
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37089r611232_chk'
  tag severity: 'high'
  tag gid: 'V-233904'
  tag rid: 'SV-233904r621666_rule'
  tag stig_id: 'IDNS-8X-500007'
  tag gtitle: 'SRG-APP-000176-DNS-000096'
  tag fix_id: 'F-37054r611233_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
