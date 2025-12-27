control 'SV-225264' do
  title 'PowerShell script block logging must be enabled on Windows 2012/2012 R2.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts. This can provide additional detail when malware has run on a system.

PowerShell 5.x supports script block logging. PowerShell 4.0 with the addition of patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 adds support for script block logging.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\

Value Name: EnableScriptBlockLogging

Value Type: REG_DWORD
Value: 0x00000001 (1)

PowerShell 4.0 requires the installation of patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012. 

If the patch is not installed on systems with PowerShell 4.0, this is a finding.

PowerShell 5.x does not require the installation of an additional patch.'
  desc 'fix', 'Configure the following registry value as specified.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\

Value Name: EnableScriptBlockLogging

Value Type: REG_DWORD
Value: 0x00000001 (1)

Administrative templates from later versions of Windows include a group policy setting for this. Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Script Block Logging" to "Enabled". 

Install patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 on systems with PowerShell 4.0. 

PowerShell 5.x does not require the installation of an additional patch.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-26963r471134_chk'
  tag severity: 'medium'
  tag gid: 'V-225264'
  tag rid: 'SV-225264r569185_rule'
  tag stig_id: 'WN12-00-000210'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-26951r471135_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00021']
  tag 'documentable'
  tag legacy: ['SV-95183', 'V-80475']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
