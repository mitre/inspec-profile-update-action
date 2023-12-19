control 'SV-226310' do
  title 'The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.'
  desc 'Allowing more than several seconds makes the computer vulnerable to a potential attack from someone walking up to the console to attempt to log on to the system before the lock takes effect.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: ScreenSaverGracePeriod

Value Type: REG_SZ
Value: 5 (or less)'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)" to "5" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28012r476774_chk'
  tag severity: 'low'
  tag gid: 'V-226310'
  tag rid: 'SV-226310r794599_rule'
  tag stig_id: 'WN12-SO-000046'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28000r476775_fix'
  tag 'documentable'
  tag legacy: ['SV-52930', 'V-4442']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
