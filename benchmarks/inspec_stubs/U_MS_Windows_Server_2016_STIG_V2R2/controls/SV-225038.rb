control 'SV-225038' do
  title 'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.'
  desc 'check', "If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
 
Value Name: scremoveoption

Value Type: REG_SZ
Value: 1 (Lock Workstation) or 2 (Force Logoff)

If configuring this on servers causes issues, such as terminating users' remote sessions, and the organization has a policy in place that any other sessions on the servers, such as administrative console logons, are manually locked or logged off when unattended or not in use, this would be acceptable. This must be documented with the ISSO."
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive logon: Smart card removal behavior" to "Lock Workstation" or "Force Logoff".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26729r466016_chk'
  tag severity: 'medium'
  tag gid: 'V-225038'
  tag rid: 'SV-225038r569186_rule'
  tag stig_id: 'WN16-SO-000180'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26717r466017_fix'
  tag 'documentable'
  tag legacy: ['SV-88473', 'V-73807']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
