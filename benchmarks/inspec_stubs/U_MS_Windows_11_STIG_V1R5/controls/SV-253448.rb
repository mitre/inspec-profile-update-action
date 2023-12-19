control 'SV-253448' do
  title 'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: SCRemoveOption

Value Type: REG_SZ
Value: 1 (Lock Workstation) or 2 (Force Logoff)

This can be left not configured or set to "No action" on workstations with the following conditions. This must be documented with the ISSO.
-The setting cannot be configured due to mission needs, or because it interferes with applications.
-Policy must be in place that users manually lock workstations when leaving them unattended.
-The screen saver is properly configured to lock as required.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive logon: Smart card removal behavior" to "Lock Workstation" or "Force Logoff".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56901r829426_chk'
  tag severity: 'medium'
  tag gid: 'V-253448'
  tag rid: 'SV-253448r829428_rule'
  tag stig_id: 'WN11-SO-000095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56851r829427_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
