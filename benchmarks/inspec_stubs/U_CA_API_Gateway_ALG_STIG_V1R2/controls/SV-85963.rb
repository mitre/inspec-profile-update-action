control 'SV-85963' do
  title 'The CA API Gateway must protect audit information from unauthorized deletion.'
  desc 'If audit data becomes compromised, forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. This requirement can be achieved through multiple methods, which will depend on system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audited events are protected by default by only allowing access to the audited events to authorized users of the CA API Gateway - Policy Manager assigned to the role of "View Audit Records". Those users must be granted access by an administrator and must be approved for access to the audited events by the organization. Users needing access to the deletion of audited events must be explicitly granted the privileges to do so.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Select "Tasks" from the main menu and choose "Manage Roles". 

Verify that only authorized users have been given the "View Audit Records" role.

If unauthorized users are granted this role, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager as an administrator. 

Select "Tasks" from the main menu and chose "Manage Roles".

Select the "View Audit Records" Role and Add/Assign the users that are authorized to view the audited events as per organizational policy.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71339'
  tag rid: 'SV-85963r1_rule'
  tag stig_id: 'CAGW-GW-000250'
  tag gtitle: 'SRG-NET-000100-ALG-000058'
  tag fix_id: 'F-77649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
