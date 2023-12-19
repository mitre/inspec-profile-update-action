control 'SV-225410' do
  title 'Windows 2012 R2 must include command line data in process creation events.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling "Include command line data for process creation events" will record the command line information with the process creation events in the log. This can provide additional detail when malware has run on a system.

'
  desc 'check', 'This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.

Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\

Value Name: ProcessCreationIncludeCmdLine_Enabled

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Audit Process Creation >> "Include command line in process creation events" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27109r471572_chk'
  tag severity: 'medium'
  tag gid: 'V-225410'
  tag rid: 'SV-225410r569185_rule'
  tag stig_id: 'WN12-CC-000139'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-27097r471573_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00021']
  tag 'documentable'
  tag legacy: ['V-43239', 'SV-56344']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
