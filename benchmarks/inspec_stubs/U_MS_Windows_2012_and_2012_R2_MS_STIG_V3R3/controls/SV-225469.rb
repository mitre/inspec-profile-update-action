control 'SV-225469' do
  title 'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.'
  desc 'check', "If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
 
Value Name: SCRemoveOption

Value Type: REG_SZ
Value: 1 (Lock Workstation) or 2 (Force Logoff)

If configuring this on servers causes issues such as terminating users' remote sessions and the site has a policy in place that any other sessions on the servers such as administrative console logons, are manually locked or logged off when unattended or not in use, this would be acceptable. This must be documented with the ISSO."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Smart card removal behavior" to  "Lock Workstation" or "Force Logoff".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27168r471749_chk'
  tag severity: 'medium'
  tag gid: 'V-225469'
  tag rid: 'SV-225469r569185_rule'
  tag stig_id: 'WN12-SO-000027'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27156r471750_fix'
  tag 'documentable'
  tag legacy: ['SV-52867', 'V-1157']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
