control 'SV-48171' do
  title 'IPSec Exemptions must be limited.'
  desc 'IPSec exemption filters allow specific traffic that may be needed by the system  for such things as Kerberos  authentication.  This setting configures Windows for specific IPSec exemptions.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.  

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic" is not set to "Multicast, broadcast and ISAKMP exempt (best for Windows XP)", this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\IPSEC\

Value Name: NoDefaultExempt

Value Type: REG_DWORD
Value: 1)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic" to "Multicast, broadcast and ISAKMP exempt (best for Windows XP)".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44871r1_chk'
  tag severity: 'low'
  tag gid: 'V-14232'
  tag rid: 'SV-48171r2_rule'
  tag stig_id: 'WN08-SO-000042'
  tag gtitle: 'IPSec Exemptions'
  tag fix_id: 'F-41309r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
