control 'SV-206823' do
  title 'The Voice Video Session Manager must protect session (call) records from unauthorized modification.'
  desc 'If session records were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. To ensure the veracity of session records, the information system and/or the application must protect session information from unauthorized modification. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.'
  desc 'check', 'Verify the Voice Video Session Manager protects session records from unauthorized modification.

If the Voice Video Session Manager does not protect session records from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager protect session records from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7078r364658_chk'
  tag severity: 'medium'
  tag gid: 'V-206823'
  tag rid: 'SV-206823r508661_rule'
  tag stig_id: 'SRG-NET-000099-VVSM-00041'
  tag gtitle: 'SRG-NET-000099'
  tag fix_id: 'F-7078r364659_fix'
  tag 'documentable'
  tag legacy: ['SV-76571', 'V-62081']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
