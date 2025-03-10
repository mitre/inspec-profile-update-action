control 'SV-214171' do
  title 'The Infoblox system implementation must enforce approved authorizations for controlling the flow of information between DNS servers and between DNS servers and DNS clients based on DNSSEC policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all application information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application-specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.

Within the context of DNS, this is applicable in terms of controlling the flow of DNS information between systems, such as DNS zone transfers.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Review the Infoblox DNS configuration to verify only approved communications are allowed. Usage of Access Control Lists to control clients, DNS zone transfer configuration to systems external to the Infoblox grid, and grid member configuration can be used to control communications as desired.

Infoblox systems within the same Grid utilize internal database transfer and do not perform zone transfers.

If all systems are within the same Infoblox Grid, this is not a finding.'
  desc 'fix', 'Zone transfers can be restricted at the Grid, Member, and Zone level. Configuration is inherited and can be overridden if necessary to construct the appropriate access control. 

Grid level configuration: Navigate to Data Management >> DNS >> Zones tab.
Click "Grid DNS Properties", and toggle Advanced Mode.

Member level configuration: Navigate to Data Management >> DNS >> Members/Servers tab.
Click "Edit" to review each member with the DNS service status of "Running". 

Zone level Configuration: Navigate to Data Management >> DNS >> Zones tab.
Select the "Zone Transfers" tab.
Click "Override" to set permissions for "Allow zone transfers to".

Configure IPv4, IPv6 networks, addresses, TSIG keys to restrict zone transfers.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15386r295779_chk'
  tag severity: 'medium'
  tag gid: 'V-214171'
  tag rid: 'SV-214171r612370_rule'
  tag stig_id: 'IDNS-7X-000240'
  tag gtitle: 'SRG-APP-000215-DNS-000003'
  tag fix_id: 'F-15384r295780_fix'
  tag 'documentable'
  tag legacy: ['V-68537', 'SV-83027']
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
