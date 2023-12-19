control 'SV-32303' do
  title 'The Smart Card removal option will be configured to Force Logoff or Lock Workstation.'
  desc 'Determines what should happen when the smart card for a logged-on user is removed from the smart card reader.

The options are:
- No Action
- Lock Workstation
- Force Logoff'
  desc 'check', 'Servers - Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “Interactive logon: Smart card removal behavior” is not set to “Lock Workstation”, or “Force Logoff”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
	
Value Name:  SCRemoveOption

Value Type:  REG_SZ
Value:  1 (Lock Workstation) or 2 (Force Logoff)

Documentable Explanation:  If configuring this on servers causes issues such as terminating users’ remote sessions and the site has a policy in place that any other sessions on the servers such as administrative console logons are manually locked or logged off when unattended or not in use, this would be acceptable.  This will be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive logon: Smart card removal behavior” to  “Lock Workstation” or “Force Logoff”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-27008r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1157'
  tag rid: 'SV-32303r1_rule'
  tag gtitle: 'Smart Card Removal Option'
  tag fix_id: 'F-105r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
