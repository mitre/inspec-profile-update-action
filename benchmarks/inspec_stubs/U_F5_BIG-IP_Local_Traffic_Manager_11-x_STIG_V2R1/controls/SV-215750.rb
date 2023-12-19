control 'SV-215750' do
  title 'The BIG-IP Core implementation must be configured to protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', "Verify the BIG-IP Core is configured to protect audit information from unauthorized modification.

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Under 'Log Access', verify unauthorized roles are set to 'Deny'.

If the BIG-IP Core is not configured to protect audit information from unauthorized modification, this is a finding."
  desc 'fix', 'Configure the BIG-IP Core to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16942r291063_chk'
  tag severity: 'medium'
  tag gid: 'V-215750'
  tag rid: 'SV-215750r557356_rule'
  tag stig_id: 'F5BI-LT-000057'
  tag gtitle: 'SRG-NET-000099-ALG-000057'
  tag fix_id: 'F-16940r291064_fix'
  tag 'documentable'
  tag legacy: ['V-60281', 'SV-74711']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
