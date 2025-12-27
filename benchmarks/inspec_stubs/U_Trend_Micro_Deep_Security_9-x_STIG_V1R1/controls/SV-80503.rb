control 'SV-80503' do
  title 'Trend Deep Security must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit records are generated when successful/unsuccessful attempts to modify security objects occur.

Review the system using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to modify security objects.

If the options for “Record” and “Forward” are not enabled for successful/unsuccessful attempts to modify security objects, this is a finding'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records when successful/unsuccessful attempts to modify security objects occur.

Configure the alert using the Administration >> System Settings >> System Events for successful/unsuccessful attempts to modify security objects. Select the “Record” and “Forward” options for the following:

- Event ID: 116  Rule Update Applied  
- Event ID: 180  Alert Type Updated  
- Event ID: 191  Alert Changed  
- Event ID: Relay Group Assigned to Computer
- Event ID: 290  Group Added  
- Event ID: 292  Group Updated
- Event ID: 306  Rebuild Baseline Requested  
- Event ID: 352  Policy Updated  
- Event ID: 378  Virtual Machine unprotected after move to another ESXi  
- Event ID: 412  Firewall Rule Updated  
- Event ID: 422  Firewall Stateful Configuration Updated  
- Event ID: 462  Application Type Updated  
- Event ID: 472  Intrusion Prevention Rule Updated  
- Event ID: 482  Integrity Monitoring Rule Updated  
- Event ID: 492  Log Inspection Rule Updated  
- Event ID: 507  Context Updated  
- Event ID: 512  IP List Updated  
- Event ID: 522  Port List Updated  
- Event ID: 532  MAC List Updated  
- Event ID: 542  Proxy Updated  
- Event ID: 552  Schedule Updated  
- Event ID: 575  Asset Value Updated  
- Event ID: 622  Access from Primary Tenant Enabled  
- Event ID: 623  Access from Primary Tenant Disabled  
- Event ID: 711  Agent Software Deployed  
- Event ID: 713  Agent Software Removed  
- Event ID: 720  Policy Sent  
- Event ID: 734  Computer Clock Change  
- Event ID: 942  Auto-Tag Rule Updated 
- Event ID: 1502  Malware Scan Configuration Updated  
- Event ID: 1512  File Extension List Updated  
- Event ID: 1517  File List Updated  
- Event ID: 1550  Web Reputation Settings Updated  
- Event ID: 1554  Firewall Stateful Configuration Updated 
- Event ID: 1555  Intrusion Prevention Configuration Updated 
- Event ID: 2002  Scan Cache Configuration Object Updated'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66661r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66013'
  tag rid: 'SV-80503r1_rule'
  tag stig_id: 'TMDS-00-000355'
  tag gtitle: 'SRG-APP-000496'
  tag fix_id: 'F-72089r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
