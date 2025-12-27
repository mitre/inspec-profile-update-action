control 'SV-77415' do
  title 'Riverbed Optimization System (RiOS) must protect audit information from unauthorized modification.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit network device activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.'
  desc 'check', 'Verify that RiOS is configured to protect audit information from unauthorized modification.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the "View" icon next to each user name
Verify that the Control "Basic Diagnostics" is set according to the authorization level of the user

If the control "Basic Diagnostics" is not set according to the authorization level of the user, this is a finding.'
  desc 'fix', 'Configure RiOS to protect audit information from unauthorized modification.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the user name that needs to have modified permissions
Set the control "Basic Diagnostics" according to the authorization level of the user.

Click "Apply"
Navigate to the top of the web page and click "Save" to write changes to memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62925'
  tag rid: 'SV-77415r1_rule'
  tag stig_id: 'RICX-DM-000062'
  tag gtitle: 'SRG-APP-000119-NDM-000236'
  tag fix_id: 'F-68843r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
