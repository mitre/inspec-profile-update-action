control 'SV-225473' do
  title 'The amount of idle time required before suspending a session must be properly set.'
  desc 'Open sessions can increase the avenues of attack on a system.  This setting is used to control when a computer disconnects an inactive SMB session.  If client activity resumes, the session is automatically reestablished.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  autodisconnect

Value Type:  REG_DWORD
Value:  0x0000000f (15) (or less)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft Network Server: Amount of idle time required before suspending session" to "15" minutes or less.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27172r471761_chk'
  tag severity: 'low'
  tag gid: 'V-225473'
  tag rid: 'SV-225473r852251_rule'
  tag stig_id: 'WN12-SO-000031'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-27160r471762_fix'
  tag 'documentable'
  tag legacy: ['SV-52878', 'V-1174']
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
