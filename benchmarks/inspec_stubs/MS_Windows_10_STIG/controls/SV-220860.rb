control 'SV-220860' do
  title 'PowerShell script block logging must be enabled on Windows 10.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts.  This can provide additional detail when malware has run on a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\

Value Name: EnableScriptBlockLogging

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Script Block Logging" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22575r555065_chk'
  tag severity: 'medium'
  tag gid: 'V-220860'
  tag rid: 'SV-220860r569187_rule'
  tag stig_id: 'WN10-CC-000326'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-22564r555066_fix'
  tag 'documentable'
  tag legacy: ['V-68819', 'SV-83411']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
