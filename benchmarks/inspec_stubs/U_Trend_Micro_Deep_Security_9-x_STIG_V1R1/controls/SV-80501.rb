control 'SV-80501' do
  title 'Trend Deep Security must generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit records are generated when successful/unsuccessful attempts to modify privileges occur.

Review the system using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to delete privileges. 

If the options for “Record” and “Forward” are not enabled for successful/unsuccessful attempts to delete privileges, this is a finding'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records when successful/unsuccessful attempts to modify privileges occur.

Configure the alert using the Administration >> System Settings >> System Events for the successful/unsuccessful attempts to delete privileges. Select the  “Record” and “Forward” options for the following:

- Event ID: 102  Trend Micro Deep Security Customer Account Changed  
- Event ID: 130  Credentials Generated
- Event ID: 131  Credential Generation Failed
- Event ID: 290  Group Added  
- Event ID: 291  Group Removed  
- Event ID: 291  Group Removed  
- Event ID: 652  User Updated  
- Event ID:  660  Role Created  
- Event ID: 651  User Deleted  
- Event ID: 661  Role Deleted  
- Event ID: 662  Role Updated  
- Event ID: 663  Roles Imported  
- Event ID: 1900  Cloud Account Added  
- Event ID: 1901  Cloud Account Removed
- Event ID: 1902  Cloud Account Updated'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66659r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66011'
  tag rid: 'SV-80501r1_rule'
  tag stig_id: 'TMDS-00-000350'
  tag gtitle: 'SRG-APP-000495'
  tag fix_id: 'F-72087r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
