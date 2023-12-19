control 'SV-223251' do
  title 'SharePoint must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

Accordingly, a risk assessment is used in determining the authentication needs of the organization.

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.'
  desc 'check', 'Review the SharePoint configuration to ensure non-organizational users (or processes acting on behalf of non-organizational users) are uniquely identified and authenticated.

Navigate to Central Administration website.

Click on "Manage web applications".

Click the web application name.

Click the "Authentication Providers" button in the "Web Applications" ribbon.

Click each Zone, and verify that the "Enable anonymous access" check box is not selected.

If it is selected and the web application zone is not defined in the system security plan as allowing anonymous access, this is a finding.

Repeat steps for each web application.'
  desc 'fix', 'Configure SharePoint to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Navigate to Central Administration website.

Click on "Manage web applications".

Click the web application name.

Click the "Authentication Providers" button in the "Web Applications" ribbon.

Click each Zone, and clear the "Enable anonymous access" check box.

Click "Save".

Repeat steps for each web application.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24924r430813_chk'
  tag severity: 'medium'
  tag gid: 'V-223251'
  tag rid: 'SV-223251r612235_rule'
  tag stig_id: 'SP13-00-000080'
  tag gtitle: 'SRG-APP-000180'
  tag fix_id: 'F-24912r430814_fix'
  tag 'documentable'
  tag legacy: ['SV-74393', 'V-59963']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
