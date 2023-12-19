control 'SV-80371' do
  title 'Trend Deep Security must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Review the Trend Deep Security server to ensure session auditing upon startup is initiated.

Verify the following events within the Administration >> System Settings >> System Events, are set to “Record.”
600 User Signed In
601 User Signed Out
602 User Timed Out
603 User Locked Out
608 User Session Validation Failed
610 User Session Validated

If these settings are not set to “Record”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to initiate session auditing upon startup.

Go to Administration >> System Settings >> System Events, and set the following settings to “Record.”
600 User Signed In
601 User Signed Out
602 User Timed Out
603 User Locked Out
608 User Session Validation Failed
610 User Session Validated'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66529r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65881'
  tag rid: 'SV-80371r1_rule'
  tag stig_id: 'TMDS-00-000075'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-71957r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
