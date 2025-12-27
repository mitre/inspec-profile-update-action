control 'SV-225490' do
  title 'The system must generate an audit event when the audit log reaches a percentage of full threshold.'
  desc 'When the audit log reaches a given percent full, an audit event is written to the security log.  It is recorded as a successful audit event under the category of System.  This option may be especially useful if the audit logs are set to be cleared manually.'
  desc 'check', 'If the system is configured to write to an audit server, or is configured to automatically archive full logs, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Eventlog\\Security\\

Value Name: WarningLevel

Value Type: REG_DWORD
Value: 90 (or less)'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to "90" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27189r471812_chk'
  tag severity: 'low'
  tag gid: 'V-225490'
  tag rid: 'SV-225490r569185_rule'
  tag stig_id: 'WN12-SO-000049'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-27177r471813_fix'
  tag 'documentable'
  tag legacy: ['V-4108', 'SV-52923']
  tag cci: ['CCI-000139', 'CCI-001855', 'CCI-001858']
  tag nist: ['AU-5 a', 'AU-5 (1)', 'AU-5 (2)']
end
