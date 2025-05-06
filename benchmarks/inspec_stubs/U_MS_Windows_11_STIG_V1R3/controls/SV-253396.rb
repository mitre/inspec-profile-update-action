control 'SV-253396' do
  title 'Explorer Data Execution Prevention must be enabled.'
  desc 'Data Execution Prevention (DEP) provides additional protection by performing checks on memory to help prevent malicious code from running. This setting will prevent Data Execution Prevention from being turned off for File Explorer.'
  desc 'check', 'The default behavior is for data execution prevention to be turned on for file explorer.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoDataExecutionPrevention

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for data execution prevention to be turned on for file explorer.

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Turn off Data Execution Prevention for Explorer" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56849r829270_chk'
  tag severity: 'medium'
  tag gid: 'V-253396'
  tag rid: 'SV-253396r829272_rule'
  tag stig_id: 'WN11-CC-000215'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-56799r829271_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
