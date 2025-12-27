control 'SV-223171' do
  title 'Telemetry archive must be disabled.'
  desc 'The Telemetry feature provides this capability by sending performance and usage info to Mozilla. As you use Firefox, Telemetry measures and collects non-personal information, such as performance, hardware, usage and customizations. It then sends this information to Mozilla on a daily basis and we use it to improve Firefox.'
  desc 'check', 'Type "about:config" in the address bar, verify that the preference name “toolkit.telemetry.archive.enabled" is set to “false” and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “toolkit.telemetry.archive.enabled" is set and locked to the value of “false”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24844r531330_chk'
  tag severity: 'medium'
  tag gid: 'V-223171'
  tag rid: 'SV-223171r612236_rule'
  tag stig_id: 'DTBF205'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24832r531331_fix'
  tag 'documentable'
  tag legacy: ['SV-111839', 'V-102877']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
