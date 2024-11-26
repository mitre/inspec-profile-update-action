control 'SV-226281' do
  title 'Outgoing secure channel traffic must be signed when possible.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked.  If this policy is enabled, outgoing secure channel traffic will be signed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: SignSecureChannel

Value Type: REG_DWORD
Value: 1

If the value for "Domain Member: Digitally encrypt or sign secure channel data (always)" is set to "Enabled", this can be NA (see V-6831).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Digitally sign secure channel data (when possible)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27983r476687_chk'
  tag severity: 'medium'
  tag gid: 'V-226281'
  tag rid: 'SV-226281r794568_rule'
  tag stig_id: 'WN12-SO-000014'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-27971r476688_fix'
  tag 'documentable'
  tag legacy: ['SV-52872', 'V-1164']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
