control 'SV-29732' do
  title 'Unauthorized registry paths and sub-paths are remotely accessible.'
  desc 'The registry is a database for computer configuration information, much of which is sensitive. An attacker could use this to facilitate unauthorized activities. To reduce the risk of this happening, it is also lowered by the fact that the default ACLs assigned throughout the registry are fairly restrictive and they help to protect it from access by unauthorized users.'
  desc 'check', "Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network access: Remotely accessible registry paths and sub-paths” contains entries besides the following, then this is a finding:

Software\\Microsoft\\OLAP Server
Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib
Software\\Microsoft\\Windows NT\\CurrentVersion\\Print
Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows
System\\CurrentControlSet\\Control\\ContentIndex
System\\CurrentControlSet\\Control\\Print\\Printers
System\\CurrentControlSet\\Control\\Terminal Server
System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig
System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration
System\\CurrentControlSet\\Services\\Eventlog
System\\CurrentControlSet\\Services\\Sysmonlog

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths\\

Value Name:  Machine

Value Type:  REG_MULTI_SZ
Value:  As defined in policy above

Note: Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the IAO, this would not be a finding.  Documentation should contain supporting information from the vendor's instructions."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Remotely accessible registry paths and sub-paths” as specified in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-347r1_chk'
  tag severity: 'high'
  tag gid: 'V-4443'
  tag rid: 'SV-29732r1_rule'
  tag gtitle: 'Remotely Accessible Registry Paths and Sub-Paths'
  tag fix_id: 'F-5739r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
