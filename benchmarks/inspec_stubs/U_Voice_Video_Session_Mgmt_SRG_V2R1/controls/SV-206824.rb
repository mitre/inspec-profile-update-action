control 'SV-206824' do
  title 'The Voice Video Session Manager must protect session (call) records from unauthorized deletion.'
  desc 'If session records were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. To ensure the veracity of session records, the information system and/or the application must protect session information from unauthorized modification. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.'
  desc 'check', 'Verify the Voice Video Session Manager protects session records from unauthorized deletion.

If the Voice Video Session Manager does not protect session records from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to protect session records from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7079r364661_chk'
  tag severity: 'medium'
  tag gid: 'V-206824'
  tag rid: 'SV-206824r508661_rule'
  tag stig_id: 'SRG-NET-000100-VVSM-00040'
  tag gtitle: 'SRG-NET-000100'
  tag fix_id: 'F-7079r364662_fix'
  tag 'documentable'
  tag legacy: ['V-62083', 'SV-76573']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
