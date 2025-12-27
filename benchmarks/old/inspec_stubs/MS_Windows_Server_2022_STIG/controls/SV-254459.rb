control 'SV-254459' do
  title 'Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.'
  desc 'check', "If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
 
Value Name: scremoveoption

Value Type: REG_SZ
Value: 1 (Lock Workstation) or 2 (Force Logoff)

If configuring this on servers causes issues, such as terminating users' remote sessions, and the organization has a policy in place that any other sessions on the servers, such as administrative console logons, are manually locked or logged off when unattended or not in use, this would be acceptable. This must be documented with the Information System Security Officer (ISSO)."
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Interactive logon: Smart card removal behavior to "Lock Workstation" or "Force Logoff".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57944r849191_chk'
  tag severity: 'medium'
  tag gid: 'V-254459'
  tag rid: 'SV-254459r849193_rule'
  tag stig_id: 'WN22-SO-000150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57895r849192_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
