control 'SV-225375' do
  title 'Explorer Data Execution Prevention must be enabled.'
  desc 'Data Execution Prevention (DEP) provides additional protection by performing  checks on memory to help prevent malicious code from running.  This setting will prevent Data Execution Prevention from being turned off for File Explorer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoDataExecutionPrevention

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off Data Execution Prevention for Explorer" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27074r471467_chk'
  tag severity: 'medium'
  tag gid: 'V-225375'
  tag rid: 'SV-225375r852217_rule'
  tag stig_id: 'WN12-CC-000089'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-27062r471468_fix'
  tag 'documentable'
  tag legacy: ['SV-53125', 'V-21980']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
