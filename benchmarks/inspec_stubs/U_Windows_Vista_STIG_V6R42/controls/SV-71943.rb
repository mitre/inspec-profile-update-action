control 'SV-71943' do
  title 'The maximum number of error reports to queue on a system must be configured to 50 or greater.'
  desc 'The error reporting queue is stored locally on the system and contains the error reports until they have been manually removed or automatically sent to the local collector or DOD-wide collector (if defined).  Once a report has been sent to a collector, it is moved to the report archive.  Old reports are deleted as new ones arrive once the maximum limit has been met.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  MaxQueueCount

Type:  REG_DWORD
Value:  0x00000032 (50)  (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled" with "Maximum number of reports to queue:" set to "50" or greater.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58371r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57473'
  tag rid: 'SV-71943r1_rule'
  tag stig_id: 'WINER-000015'
  tag gtitle: 'WINER-000015'
  tag fix_id: 'F-62739r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
