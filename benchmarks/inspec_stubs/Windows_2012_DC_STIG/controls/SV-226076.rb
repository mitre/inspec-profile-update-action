control 'SV-226076' do
  title 'Time synchronization must be enabled on the domain controller.'
  desc 'When a directory service using multi-master replication (such as AD) executes on computers that do not have synchronized time, directory data may be corrupted or updated invalidly.

The lack of synchronized time could lead to audit log data that is misleading, inconclusive, or unusable. In cases of intrusion this may invalidate the audit data as a source of forensic evidence in an incident investigation.

In AD, the lack of synchronized time could prevent clients from logging on or accessing server resources as a result of Kerberos requirements related to time variance.'
  desc 'check', 'Determine if a time synchronization tool has been implemented on the Windows domain controller.

If  the Windows Time Service is used, verify the following registry values.  If they are not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE

Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient\\
Value Name: Enabled
Type: REG_DWORD
Value: 1

Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Parameters\\
Value Name: Type
Type: REG_SZ
Value: NT5DS (preferred), NTP or Allsync

If these Windows checks indicate a finding because the NtpClient is not enabled, determine if an alternate time synchronization tool is installed and enabled.

If the Windows Time Service is not enabled and no alternate tool is enabled, this is a finding.'
  desc 'fix', 'Ensure the Windows Time Service is configured as follows or install and enable another time synchronization tool.

Registry Hive: HKEY_LOCAL_MACHINE

Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient\\
Value Name: Enabled
Type: REG_DWORD
Value: 1

Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\ Parameters\\
Value Name: Type
Type: REG_SZ
Value: NT5DS (preferred), NTP or Allsync'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27778r475551_chk'
  tag severity: 'medium'
  tag gid: 'V-226076'
  tag rid: 'SV-226076r852062_rule'
  tag stig_id: 'WN12-AD-000007-DC'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-27766r794806_fix'
  tag 'documentable'
  tag legacy: ['SV-51181', 'V-8322']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
