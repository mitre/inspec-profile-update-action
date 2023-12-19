control 'SV-80507' do
  title 'Trend Deep Security must generate audit records when successful/unsuccessful attempts to modify security levels occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit records are generated when successful/unsuccessful attempts to modify security levels occur.

Review the system using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to modify security levels. 

If the “Record” and “Forward” options for successful/unsuccessful attempts to modify security levels are not enabled, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records when successful/unsuccessful attempts to modify security levels occur.

Configure the alert using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to modify security levels. Select the “Record” and “Forward” options for the following:

- Event ID: 253  Policy Assigned to Computer
- Event ID: 350  Policy Created  
- Event ID: 352  Policy Updated  
- Event ID:  720  Policy Sent  
- Event ID: 410  Firewall Rule Created  
- Event ID: 420  Firewall Stateful Configuration Created  
- Event ID: 460  Application Type Created  
- Event ID: 470  Intrusion Prevention Rule Created  
- Event ID: 480  Integrity Monitoring Rule Created  
- Event ID: 490  Log Inspection Rule Created  
- Event ID: 495  Log Inspection Decoder Created  
- Event ID: 573  Asset Value Created  
- Event ID: 1500  Malware Scan Configuration Created  
- Event ID: 1510  File Extension List Created'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66017'
  tag rid: 'SV-80507r1_rule'
  tag stig_id: 'TMDS-00-000360'
  tag gtitle: 'SRG-APP-000497'
  tag fix_id: 'F-72093r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
