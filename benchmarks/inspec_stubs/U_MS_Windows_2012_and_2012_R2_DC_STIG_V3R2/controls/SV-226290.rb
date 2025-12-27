control 'SV-226290' do
  title 'Caching of logon credentials must be limited.'
  desc "The default Windows configuration caches the last logon credentials for users who log on interactively to a system.  This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable.  Even though the credential cache is well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain."
  desc 'check', 'If the system is not a member of a domain, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  CachedLogonsCount

Value Type:  REG_SZ
Value:  4 (or less)'
  desc 'fix', 'If the system is not a member of a domain, this is NA.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)" to "4" logons or less.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27992r476714_chk'
  tag severity: 'low'
  tag gid: 'V-226290'
  tag rid: 'SV-226290r569184_rule'
  tag stig_id: 'WN12-SO-000024'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27980r476715_fix'
  tag 'documentable'
  tag legacy: ['SV-52846', 'V-1090']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
