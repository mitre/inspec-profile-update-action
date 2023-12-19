control 'SV-68693' do
  title 'The ALG must protect audit information from unauthorized deletion.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

This requirement does not apply to audit logs generated on behalf of the device itself (device management).'
  desc 'check', 'Verify the ALG protects audit information from unauthorized deletion.

If the ALG does not protect audit information from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the ALG to protect audit information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55063r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54447'
  tag rid: 'SV-68693r1_rule'
  tag stig_id: 'SRG-NET-000100-ALG-000058'
  tag gtitle: 'SRG-NET-000100-ALG-000058'
  tag fix_id: 'F-59301r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
