control 'SV-222556' do
  title 'The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system.

Non-organizational users include all information system users other than organizational users which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors and guest researchers).

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.'
  desc 'check', 'Review the application documentation and interview the application administrator.

If the application does not host non-organizational users, this requirement is not applicable.

Review the application and verify authentication is enabled and required in order for users to access the application.

Review the application user base and determine if all user accounts are documented and assigned to a unique individual.

Review risk acceptance documentation to determine if there are specific accesses identified that do not require authentication.

If the application does not identify and authenticate non-organizational users and there is no risk acceptance documentation approving the exception, this is a finding.'
  desc 'fix', 'Configure the application to identify and authenticate all non-organizational users.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24226r493576_chk'
  tag severity: 'medium'
  tag gid: 'V-222556'
  tag rid: 'SV-222556r879617_rule'
  tag stig_id: 'APSC-DV-001870'
  tag gtitle: 'SRG-APP-000180'
  tag fix_id: 'F-24215r493577_fix'
  tag 'documentable'
  tag legacy: ['V-70161', 'SV-84783']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
