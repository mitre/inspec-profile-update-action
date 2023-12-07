control 'SV-226276' do
  title 'Auditing of Backup and Restore Privileges must be turned off.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.  
This setting prevents the system from generating audit events for every file backed up or restored, which could fill the security log in Windows, making it difficult to identify actual issues.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: FullPrivilegeAuditing

Value Type: REG_BINARY
Value: 00'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Audit the use of Backup and Restore privilege" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27978r476672_chk'
  tag severity: 'medium'
  tag gid: 'V-226276'
  tag rid: 'SV-226276r794552_rule'
  tag stig_id: 'WN12-SO-000008'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-27966r476673_fix'
  tag 'documentable'
  tag legacy: ['V-14229', 'SV-52943']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
