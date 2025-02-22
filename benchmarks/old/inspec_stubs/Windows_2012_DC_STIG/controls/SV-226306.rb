control 'SV-226306' do
  title 'IPSec Exemptions must be limited.'
  desc 'IPSec exemption filters allow specific traffic that may be needed by the system  for such things as Kerberos  authentication.  This setting configures Windows for specific IPSec exemptions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\IPSEC\\

Value Name: NoDefaultExempt

Value Type: REG_DWORD
Value: 3'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic" to "Only ISAKMP is exempt (recommended for Windows Server 2003)".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28008r476762_chk'
  tag severity: 'low'
  tag gid: 'V-226306'
  tag rid: 'SV-226306r794597_rule'
  tag stig_id: 'WN12-SO-000042'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27996r476763_fix'
  tag 'documentable'
  tag legacy: ['SV-52945', 'V-14232']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
