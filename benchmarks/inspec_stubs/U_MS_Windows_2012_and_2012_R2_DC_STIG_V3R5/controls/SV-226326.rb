control 'SV-226326' do
  title 'PKU2U authentication using online identities must be prevented.'
  desc 'PKU2U is a peer-to-peer authentication protocol.   This setting prevents online identities from authenticating to domain-joined systems.  Authentication will be centrally managed with Windows user accounts.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Control\\LSA\\pku2u\\

Value Name: AllowOnlineID

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28028r476822_chk'
  tag severity: 'medium'
  tag gid: 'V-226326'
  tag rid: 'SV-226326r794604_rule'
  tag stig_id: 'WN12-SO-000063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28016r476823_fix'
  tag 'documentable'
  tag legacy: ['SV-53178', 'V-21953']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
