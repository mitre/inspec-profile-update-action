control 'SV-71911' do
  title 'The maximum number of error reports to archive on a system must be configured to 100 or greater.'
  desc 'The retention of archived reports provides a history.  Older reports are automatically deleted as new reports are generated once the maximum limit has been met.  The archive is stored locally on the system and is created after the error report has been sent to the local collector or DOD-wide collector (if defined).'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Archive" to "Enabled" with "Maximum number of reports to store:" set to "100" or greater.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-57467'
  tag rid: 'SV-71911r1_rule'
  tag stig_id: 'WINER-000012'
  tag gtitle: 'WINER-000012'
  tag fix_id: 'F-62709r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
