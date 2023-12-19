control 'SV-83441' do
  title 'Structured Exception Handling Overwrite Protection (SEHOP) must be turned on.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications. Structured Exception Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.'
  desc 'check', 'If SEHOP is configured through the Enhanced Mitigation Experience Toolkit (EMET) (V-36706), this is NA.

Verify SEHOP is turned on.
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\

Value Name: DisableExceptionChainValidation

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\

Value Name: DisableExceptionChainValidation

Value Type: REG_DWORD
Value: 0'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-69317r3_chk'
  tag severity: 'high'
  tag gid: 'V-68847'
  tag rid: 'SV-83441r1_rule'
  tag stig_id: 'WN08-00-000150'
  tag gtitle: 'WIN00-000150'
  tag fix_id: 'F-75019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
