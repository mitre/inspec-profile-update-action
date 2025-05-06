control 'SV-77413' do
  title 'Riverbed Optimization System (RiOS) must protect audit information from any type of unauthorized read access.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the network device must protect audit information from any and all unauthorized read access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, network devices with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the device interface. If the device provides access to the audit data, the device becomes accountable for ensuring audit information is protected from unauthorized access.'
  desc 'check', 'Verify that RiOS is configured to protect audit information from any type of unauthorized read access.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the view icon next to each user name
Verify that the Control "Basic Diagnostics" is set according to the authorization level of the user

If the control "Basic Diagnostics" is not set according to the authorization level of the user, this is a finding.'
  desc 'fix', 'Configure RiOS to protect audit information from any type of unauthorized read access.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Select the user name that needs to have modified permissions
Set the control "Basic Diagnostics" according to the authorization level of the user.

Click "Apply"
Navigate to the top of the web page and click "Save" to write changes to memory'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62923'
  tag rid: 'SV-77413r1_rule'
  tag stig_id: 'RICX-DM-000061'
  tag gtitle: 'SRG-APP-000118-NDM-000235'
  tag fix_id: 'F-68841r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
