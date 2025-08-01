control 'SV-233911' do
  title 'The Infoblox DNS server implementation must enforce approved authorizations for controlling the flow of information between DNS servers and between DNS servers and DNS clients based on DNSSEC policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all application information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data.

Application-specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services or provide a message-filtering capability based on message content (e.g., implementing keyword searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information between interconnected systems in accordance with applicable policy.

Within the context of DNS, this is applicable in terms of controlling the flow of DNS information between systems, such as DNS zone transfers.'
  desc 'check', 'Review the configuration of Infoblox DNS systems and verify that communication flow is validated.

1. Review the Infoblox DNS configuration to verify that only approved communications are allowed.   
2. Use of Access Control Lists to control clients, DNS zone transfer configuration to systems external to the Infoblox Grid, and Grid member configuration can be used to control communications as desired. 

Infoblox systems within the same Grid use internal database updates and do not perform zone transfers. 

If all systems are within the same Infoblox Grid, this is not a finding.

If the Infoblox system is configured to perform zone transfers to non-Grid systems, access control must be used. Otherwise, this is a finding.'
  desc 'fix', 'Zone transfers can be restricted at the Grid, Member, and Zone level. Configuration is inherited and can be overridden if necessary to construct the appropriate access control. Refer to the Infoblox Administrator Guide if necessary.  

1. Grid-level configuration: Navigate to Data Management >> DNS >> Zones tab.  
2. Click "Grid DNS Properties" and toggle Advanced Mode. 
3. Member-level configuration: Navigate to Data Management >> DNS >> Members tab.  
4. Click "Edit" to review each member with the DNS service status of "Running". 
5. Zone-level configuration: Navigate to Data Management >> DNS >> Zones tab.  
6. Select the "Zone Transfers" tab.  
7. Click "Override" to set permissions for "Allow zone transfers to". 
8. Configure IPv4 and IPv6 networks, addresses, and TSIG keys to restrict zone transfers.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37096r611253_chk'
  tag severity: 'medium'
  tag gid: 'V-233911'
  tag rid: 'SV-233911r621666_rule'
  tag stig_id: 'IDNS-8X-700006'
  tag gtitle: 'SRG-APP-000215-DNS-000003'
  tag fix_id: 'F-37061r611254_fix'
  tag 'documentable'
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
