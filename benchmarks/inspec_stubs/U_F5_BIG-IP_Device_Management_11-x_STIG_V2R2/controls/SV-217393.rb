control 'SV-217393' do
  title 'The BIG-IP appliance must be configured to protect audit information from unauthorized deletion.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order to make access decisions regarding the deletion of audit data.'
  desc 'check', 'Verify the BIG-IP appliance protects audit information from any type of unauthorized deletion. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Verify authorized access is configured for each role under "Log Access".

If the BIG-IP appliance is not configured to protect audit information from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to protect audit information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18618r290733_chk'
  tag severity: 'medium'
  tag gid: 'V-217393'
  tag rid: 'SV-217393r879578_rule'
  tag stig_id: 'F5BI-DM-000077'
  tag gtitle: 'SRG-APP-000120-NDM-000237'
  tag fix_id: 'F-18616r290734_fix'
  tag 'documentable'
  tag legacy: ['SV-74561', 'V-60131']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
