control 'SV-206688' do
  title 'The firewall must protect the traffic log from unauthorized deletion of local log files and log records.'
  desc 'If audit data were to become compromised, forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. This can be achieved through multiple methods, which will depend on system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

This requirement does not apply to traffic logs generated on behalf of the device itself (device management).'
  desc 'check', "Verify the firewall's fine-grained permissions are configured to prevent unauthorized deletion of local log files or log records.

If the firewall does not protect traffic log records and log files from unauthorized deletion while stored locally, this is a finding."
  desc 'fix', 'Validate the firewall includes a baseline cryptographic module that provides confidentiality and integrity services for authentication and for protecting communications with adjacent systems.

Configure role-based, fine-grained permissions management for controlling commands needed to delete log files and records.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6945r297843_chk'
  tag severity: 'medium'
  tag gid: 'V-206688'
  tag rid: 'SV-206688r604133_rule'
  tag stig_id: 'SRG-NET-000100-FW-000023'
  tag gtitle: 'SRG-NET-000100'
  tag fix_id: 'F-6945r297844_fix'
  tag 'documentable'
  tag legacy: ['SV-94165', 'V-79459']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
