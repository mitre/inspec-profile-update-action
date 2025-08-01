control 'SV-225517' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27216r471893_chk'
  tag severity: 'medium'
  tag gid: 'V-225517'
  tag rid: 'SV-225517r569185_rule'
  tag stig_id: 'WN12-SO-000079'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-27204r471894_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag legacy: ['SV-52948', 'V-14236']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
