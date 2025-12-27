control 'SV-228868' do
  title 'The Palo Alto Networks security platform must continuously monitor inbound communications traffic crossing internal security boundaries.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

Internal monitoring includes the observation of events occurring on the network crosses internal boundaries at managed interfaces such as web content filters. Depending on the type of ALG, organizations can monitor information systems by monitoring audit activities, application access patterns, characteristics of access, content filtering, or unauthorized exporting of information across boundaries. Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.

Most current applications are deployed as a multi-tier architecture. The multi-tier model uses separate server machines to provide the different functions of presentation, business logic, and database.  The multi-tier architecture provides added security because a compromised web server does not provide direct access to the application itself or to the database.'
  desc 'check', 'Obtain the network architecture diagrams and identify where traffic crosses from one internal zone to another and review the configuration of the Palo Alto Networks security platform.  
The specific security policy is based on the authorized endpoints, applications, and protocols.

If it does not monitor traffic passing between zones, this is a finding.'
  desc 'fix', 'The network architecture diagrams must identify where traffic crosses from one internal zone to another. The specific security policy is based on the authorized endpoints, applications, and protocols.

To create or edit a Security Policy:
Go to Policies >> Security
Select "Add" to create a new security policy, or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31103r513899_chk'
  tag severity: 'medium'
  tag gid: 'V-228868'
  tag rid: 'SV-228868r831610_rule'
  tag stig_id: 'PANW-AG-000115'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-31080r513900_fix'
  tag 'documentable'
  tag legacy: ['V-62617', 'SV-77107']
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
