control 'SV-226340' do
  title 'User Account Control must automatically deny standard user requests for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting controls the behavior of elevation when requested by a standard user account.

'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorUser

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28042r476864_chk'
  tag severity: 'medium'
  tag gid: 'V-226340'
  tag rid: 'SV-226340r569184_rule'
  tag stig_id: 'WN12-SO-000079'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-28030r476865_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag legacy: ['SV-52948', 'V-14236']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
