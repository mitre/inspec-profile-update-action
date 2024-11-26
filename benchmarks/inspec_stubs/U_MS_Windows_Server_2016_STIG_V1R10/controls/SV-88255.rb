control 'SV-88255' do
  title 'PowerShell script block logging must be enabled.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts. This can provide additional detail when malware has run on a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\ Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\

Value Name: EnableScriptBlockLogging

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Script Block Logging" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73591'
  tag rid: 'SV-88255r1_rule'
  tag stig_id: 'WN16-CC-000490'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-80041r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
