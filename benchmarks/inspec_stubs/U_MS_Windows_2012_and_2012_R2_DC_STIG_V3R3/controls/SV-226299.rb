control 'SV-226299' do
  title 'Users must be forcibly disconnected when their logon hours expire.'
  desc 'Users must not be permitted to remain logged on to the network after they have exceeded their permitted logon hours.  In many cases, this indicates that a user forgot to log off before leaving for the day.  However, it may also indicate that a user is attempting unauthorized access at a time when the system may be less closely monitored.  Forcibly disconnecting users when logon hours expire protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: EnableForcedLogoff

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Disconnect clients when logon hours expire" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28001r476741_chk'
  tag severity: 'low'
  tag gid: 'V-226299'
  tag rid: 'SV-226299r794609_rule'
  tag stig_id: 'WN12-SO-000034'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-27989r476742_fix'
  tag 'documentable'
  tag legacy: ['V-1136', 'SV-52860']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
