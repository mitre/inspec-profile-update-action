control 'SV-80417' do
  title 'Trend Deep Security must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system. 

Non-organizational users include all information system users other than organizational users which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors and guest researchers). 

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.'
  desc 'check', "Review the Trend Deep Security server configuration to ensure non-organizational users (or processes acting on behalf of non-organizational users) are uniquely identified and authenticated.

Verify the user accounts under Administration >> User Management >> Users

If the accounts configured do not uniquely specify the organizational user's affiliation, this is a finding."
  desc 'fix', 'Configure the Trend Deep Security server to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

To help prevent inadvertent disclosure of controlled information, all contractors are identified by the inclusion of the abbreviation "ctr" and all foreign nationals are identified by the inclusion of their two character country code.  See ECAD-1 Affiliation Display

Configure the appropriate affiliation display for the specified user under Administration >> User Management >> Users
Right click the user account.
Click "Properties" and Select “User Name”. 
Enter the appropriate user identifiers.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66575r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65927'
  tag rid: 'SV-80417r1_rule'
  tag stig_id: 'TMDS-00-000170'
  tag gtitle: 'SRG-APP-000180'
  tag fix_id: 'F-72003r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
