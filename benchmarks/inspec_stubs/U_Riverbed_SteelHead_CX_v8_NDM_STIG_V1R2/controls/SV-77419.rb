control 'SV-77419' do
  title 'Riverbed Optimization System (RiOS) must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify that RiOS is configured to protect audit tools from unauthorized access.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the "View" icon next to each user name
Verify that the Control "Basic Diagnostics" is set according to the authorization level of the user

If the control "Basic Diagnostics" is not set according to the authorization level of the user, this is a finding.'
  desc 'fix', 'Configure RiOS to protect audit tools from unauthorized access.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the user name that needs to have modified permissions
Set the control "Basic Diagnostics" according to the authorization level of the user.

Click "Apply"
Navigate to the top of the web page and click "Save" to write changes to memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62929'
  tag rid: 'SV-77419r1_rule'
  tag stig_id: 'RICX-DM-000064'
  tag gtitle: 'SRG-APP-000121-NDM-000238'
  tag fix_id: 'F-68847r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
