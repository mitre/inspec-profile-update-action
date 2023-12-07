control 'SV-71657' do
  title 'The Windows Error Reporting Service must be running and configured to start automatically.'
  desc 'Windows Error Reporting information can be used to help diagnose day-to-day software issues, as well as help discover malicious code and possibly zero-day attacks on systems.'
  desc 'fix', 'Configure the Start Type of the Windows Error Reporting Service to "Automatic" and ensure the service has a status of "Started".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-56511'
  tag rid: 'SV-71657r1_rule'
  tag stig_id: 'WINER-000001'
  tag gtitle: 'WINER-000001'
  tag fix_id: 'F-62423r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
