control 'SV-253455' do
  title 'The system must be configured to prevent anonymous users from having the same rights as the Everyone group.'
  desc 'Access by anonymous users must be restricted. If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Let Everyone permissions apply to anonymous users" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56908r829447_chk'
  tag severity: 'medium'
  tag gid: 'V-253455'
  tag rid: 'SV-253455r829449_rule'
  tag stig_id: 'WN11-SO-000160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56858r829448_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
