control 'SV-80509' do
  title 'Trend Deep Security must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit records are generated when successful/unsuccessful attempts to delete privileges occur.

Review the system using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to delete privileges. 

If the “Record” and “Forward” options for successful/unsuccessful attempts to delete privileges are not enabled, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records when successful/unsuccessful attempts to delete privileges occur.

Configure the alert using the Administration >> System Settings >> System Events tab for successful/unsuccessful attempts to delete privileges. Select the  “Record” and “Forward” options for the following:

- Event ID: 124  Rule Update Deleted  
- Event ID: 661  Role Deleted  
- Event ID: 671  Contact Deleted  
- Event ID: 291  Group Removed  
- Event ID: 1901  Cloud Account Removed'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66019'
  tag rid: 'SV-80509r1_rule'
  tag stig_id: 'TMDS-00-000365'
  tag gtitle: 'SRG-APP-000499'
  tag fix_id: 'F-72095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
