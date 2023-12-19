control 'SV-68691' do
  title 'The ALG must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG protects audit information from unauthorized modification.

If the ALG does not protect audit information from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the ALG to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55061r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54445'
  tag rid: 'SV-68691r1_rule'
  tag stig_id: 'SRG-NET-000099-ALG-000057'
  tag gtitle: 'SRG-NET-000099-ALG-000057'
  tag fix_id: 'F-59299r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
