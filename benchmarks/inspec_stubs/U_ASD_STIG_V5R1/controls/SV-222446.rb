control 'SV-222446' do
  title 'The application must record a time stamp indicating when the event occurred.'
  desc 'It is important to include the time stamps for when an event occurred. Failure to include time stamps in the event logs is detrimental to forensic analysis.'
  desc 'check', 'Review the application logs.

If the time the event occurred is not included as part of the event, this is a finding.'
  desc 'fix', 'Configure the application to record the time the event occurred when recording the event.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24116r493246_chk'
  tag severity: 'medium'
  tag gid: 'V-222446'
  tag rid: 'SV-222446r508029_rule'
  tag stig_id: 'APSC-DV-000670'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24105r493247_fix'
  tag 'documentable'
  tag legacy: ['SV-83995', 'V-69373']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
