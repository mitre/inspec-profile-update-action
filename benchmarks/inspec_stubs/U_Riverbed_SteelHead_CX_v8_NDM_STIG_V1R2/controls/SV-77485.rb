control 'SV-77485' do
  title 'The application must reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives."
  desc 'check', 'Verify that RiOS is configured to reveal error messages only to authorized individuals (ISSO, ISSM, and SA).

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the view icon next to each user name
Verify that the Control "Basic Diagnostics" is set according to the authorization level of the user

If the control "Basic Diagnostics" is not set according to the authorization level of the user, this is a finding.'
  desc 'fix', 'Configure RiOS to reveal error messages only to authorized individuals (ISSO, ISSM, and SA).

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the user name that needs to have modified permissions
Set the control "Basic Diagnostics" according to the authorization level of the user

Click "Apply"
Navigate to the top of the web page and click "Save" to write changes to memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62995'
  tag rid: 'SV-77485r1_rule'
  tag stig_id: 'RICX-DM-000145'
  tag gtitle: 'SRG-APP-000267-NDM-000273'
  tag fix_id: 'F-68913r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
