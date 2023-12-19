control 'SV-71891' do
  title 'The system must be configured to archive error reports.'
  desc 'The error reporting archive is stored locally on the system, and is created after an error report has been sent to the local collector or DOD-wide collector (if defined).  This creates a backup of the error reporting.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Archive" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-57463'
  tag rid: 'SV-71891r1_rule'
  tag stig_id: 'WINER-000010'
  tag gtitle: 'WINER-000010'
  tag fix_id: 'F-62681r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
