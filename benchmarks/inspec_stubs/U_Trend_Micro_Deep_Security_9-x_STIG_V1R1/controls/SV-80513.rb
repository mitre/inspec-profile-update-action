control 'SV-80513' do
  title 'Trend Deep Security must generate audit records when successful/unsuccessful attempts to delete security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit records are generated when successful/unsuccessful attempts to delete security objects occur.

Review the system using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to delete security objects. 

If the “Record” and “Forward" options for are not enabled for successful/unsuccessful attempts to delete security objects, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records when successful/unsuccessful attempts to delete security objects occur.

Configure the alert using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to delete security objects. Select the  “Record” and “Forward” options for the following:

- Event ID: 124  Rule Update Deleted  
- Event ID: 152  Software Deleted  
- Event ID: 295  Interface Deleted  
- Event ID: 296  Interface IP Deleted  
- Event ID: 331  SSL Configuration Deleted  
- Event ID: 351  Policy Deleted  
- Event ID: 411  Firewall Rule Deleted  
- Event ID: 421  Firewall Stateful Configuration Deleted  
- Event ID: 461  Application Type Deleted  
- Event ID: 471  Intrusion Prevention Rule Deleted  
- Event ID: 481  Integrity Monitoring Rule Deleted  
- Event ID: 491  Log Inspection Rule Deleted  
- Event ID: 496  Log Inspection Decoder Deleted  
- Event ID: 506  Context Deleted  
- Event ID: 574  Asset Value Deleted  
- Event ID: 593  Relay Group Deleted  
- Event ID: 595  Event-Based Task Deleted  
- Event ID: 931  Certificate Deleted  
- Event ID: 941  Auto-Tag Rule Deleted 
- Event ID: 943  Tag Deleted  
- Event ID: 1501  Malware Scan Configuration Deleted  
- Event ID: 1501  Malware Scan Configuration Deleted  
- Event ID: 1511  File Extension List Deleted  
- Event ID: 1516  File List Deleted 
- Event ID: 1951  Tenant Deleted  
- Event ID: 1954  Tenant Database Server Deleted'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66671r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66023'
  tag rid: 'SV-80513r1_rule'
  tag stig_id: 'TMDS-00-000375'
  tag gtitle: 'SRG-APP-000501'
  tag fix_id: 'F-72099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
