control 'SV-28979' do
  title 'Caching of logon credentials must be limited.'
  desc "The default Windows configuration caches the last logon credentials for users who log on interactively to a system.  This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable.  Even though the credential cache is well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain."
  desc 'check', 'If the system is not a member of a domain, this is NA.
Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Interactive Logon: Number of previous logons to cache (in case Domain Controller is unavailable)" is not set to "2" logons or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE 
Registry Path:  \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  CachedLogonsCount

Value Type:  REG_SZ
Value:  2 (or less)'
  desc 'fix', 'If the system is not a member of a domain, this is NA.
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)" to "2" logons or less.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-59061r6_chk'
  tag severity: 'low'
  tag gid: 'V-1090'
  tag rid: 'SV-28979r3_rule'
  tag gtitle: 'Caching of logon credentials'
  tag fix_id: 'F-63551r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
