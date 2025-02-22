control 'SV-71963' do
  title 'The system must be configured to automatically consent to send all data requested by a local or DOD-wide error collection site.'
  desc 'Configuring error reporting to send all requested data ensures all relevant data associated with the error report is captured for later analysis.  This setting determines the default consent behavior of Windows Error Reporting.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Consent -> "Configure Default consent" to "Enabled" with "Send all data" selected for "Consent level".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-57477'
  tag rid: 'SV-71963r1_rule'
  tag stig_id: 'WINER-000017'
  tag gtitle: 'WINER-000017'
  tag fix_id: 'F-62759r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
