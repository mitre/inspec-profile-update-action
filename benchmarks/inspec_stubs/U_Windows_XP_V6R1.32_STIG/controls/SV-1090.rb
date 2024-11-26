control 'SV-1090' do
  title 'Caching of logon credentials is not limited.'
  desc 'The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons such as the user’s machine is disconnected from the network or domain controllers are not available. Even though the credential cache is well-protected, storing encrypted copies of users passwords on systems do not always have the same physical protection required for domain controllers. If a system is attacked, the unauthorized individual may isolate the password to a domain user account using a password-cracking program, and gain access to the domain.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies -> Security Options.

If the value for “Interactive Logon: Number of previous logons to cache (in case Domain Controller is unavailable)” is not set to “2” logons or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  CachedLogonsCount

Value Type:  REG_SZ
Value:  2'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)” to “2” logons or less.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-59r2_chk'
  tag severity: 'low'
  tag gid: 'V-1090'
  tag rid: 'SV-1090r2_rule'
  tag gtitle: 'Caching of logon credentials'
  tag fix_id: 'F-78r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
