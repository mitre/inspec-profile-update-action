control 'SV-253438' do
  title 'Outgoing secure channel traffic must be encrypted or signed.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Digitally encrypt or sign secure channel data (always)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56891r829396_chk'
  tag severity: 'medium'
  tag gid: 'V-253438'
  tag rid: 'SV-253438r829398_rule'
  tag stig_id: 'WN11-SO-000035'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-56841r829397_fix'
  tag 'documentable'
  tag cci: ['CCI-002388', 'CCI-002391']
  tag nist: ['SC-5 (3) (a)', 'SC-5 (3) (b)']
end
