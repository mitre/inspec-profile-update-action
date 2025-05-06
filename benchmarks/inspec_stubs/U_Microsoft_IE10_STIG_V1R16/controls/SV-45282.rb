control 'SV-45282' do
  title 'Participation in the Customer Experience Improvement Program must be disallowed.'
  desc "This setting controls whether users can participate in the Microsoft Customer Experience Improvement Program to help improve Microsoft applications. When users choose to participate in the Customer Experience Improvement Program (CEIP), applications automatically send information to Microsoft about how the applications are used. This information is combined with other CEIP data to help Microsoft solve problems and to improve the products and features customers use most often. This feature does not collect users' names, addresses, or any other identifying information except the IP address that is used to send the data. By default, users have the opportunity to opt into participation in the CEIP the first time they run an application. If an organization has policies that govern the use of external resources such as the CEIP, allowing users to opt in to the program might cause them to violate these policies."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Prevent participation in the Customer Experience Improvement Program" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\SQM 

Criteria: If the value DisableCustomerImprovementProgram is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Prevent participation in the Customer Experience Improvement Program" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15492'
  tag rid: 'SV-45282r1_rule'
  tag stig_id: 'DTBI315'
  tag gtitle: 'DTBI315 - Customer Experience Improvement Pgm'
  tag fix_id: 'F-38678r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
