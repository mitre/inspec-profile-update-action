control 'SV-14843' do
  title 'IPSec Exemptions are limited.'
  desc 'This check verifies that Windows is configured to limit IPSec exemptions.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 

Navigate to Local Policies -> Security Options.  

If the value for “MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic” is not set to “Multicast, broadcast and ISAKMP exempt (best for Windows XP)”, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\IPSEC\\

Value Name:  NoDefaultExempt

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic” to “Multicast, broadcast and ISAKMP exempt (best for Windows XP)”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-11577r1_chk'
  tag severity: 'low'
  tag gid: 'V-14232'
  tag rid: 'SV-14843r1_rule'
  tag gtitle: 'IPSec Exemptions'
  tag fix_id: 'F-13556r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
