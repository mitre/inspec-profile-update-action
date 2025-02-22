control 'SV-217392' do
  title 'The BIG-IP appliance must be configured to protect audit information from unauthorized modification.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit network device activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve.

To ensure the veracity of audit data, the network device must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations.

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.'
  desc 'check', 'Verify the BIG-IP appliance protects audit information from any type of unauthorized modification. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Verify authorized access is configured for each role under "Log Access".

If the BIG-IP appliance is not configured to protect audit information from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18617r290730_chk'
  tag severity: 'medium'
  tag gid: 'V-217392'
  tag rid: 'SV-217392r879577_rule'
  tag stig_id: 'F5BI-DM-000075'
  tag gtitle: 'SRG-APP-000119-NDM-000236'
  tag fix_id: 'F-18615r290731_fix'
  tag 'documentable'
  tag legacy: ['SV-74559', 'V-60129']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
