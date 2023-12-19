control 'SV-237944' do
  title 'The IBM z/VM JOURNALING statement must be properly configured.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'View system config “JOURNALING” statement.

If the “JOURNALING” statement “LOGON” operand is configured as below, this is not a finding.

Logon,
Account after 3 attempts,
See IBMZ-VM-000040 for LOCKOUT setting.

Link,
Account after 3 attempts,
Disable after 3 attempts'
  desc 'fix', 'Configure the system config “JOURNALING” statement to include the following:

Logon,
Account after 3 attempts,
See IBMZ-VM-000040 for LOCKOUT setting.

Link,
Account after 3 attempts,
Disable after 3 attempts'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41154r649670_chk'
  tag severity: 'medium'
  tag gid: 'V-237944'
  tag rid: 'SV-237944r649672_rule'
  tag stig_id: 'IBMZ-VM-001020'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-41113r649671_fix'
  tag 'documentable'
  tag legacy: ['SV-93641', 'V-78935']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
