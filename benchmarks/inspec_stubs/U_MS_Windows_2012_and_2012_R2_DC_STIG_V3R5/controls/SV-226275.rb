control 'SV-226275' do
  title 'Auditing the Access of Global System Objects must be turned off.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
This setting prevents the system from setting up a default system access control list for certain system objects, which could create a very large number of security events, filling the security log in Windows and making it difficult to identify actual issues.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: AuditBaseObjects

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Audit the access of global system objects" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27977r476669_chk'
  tag severity: 'medium'
  tag gid: 'V-226275'
  tag rid: 'SV-226275r794551_rule'
  tag stig_id: 'WN12-SO-000007'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-27965r476670_fix'
  tag 'documentable'
  tag legacy: ['SV-53129', 'V-14228']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
