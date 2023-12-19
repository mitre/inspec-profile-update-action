control 'SV-6275' do
  title 'Unauthorized registry paths are remotely accessible.'
  desc 'This is a Category 1 finding because it could give unauthorized individuals access to the Registry.  
It controls which registry paths are accessible from a remote computer.'
  desc 'check', "Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network access: Remotely accessible registry paths” contains entries besides the following, then this is a finding:

System\\CurrentControlSet\\Control\\ProductOptions 
System\\CurrentControlSet\\Control\\Print\\Printers 
System\\CurrentControlSet\\Control\\Server Applications 
System\\CurrentControlSet\\Services\\Eventlog
Software\\Microsoft\\OLAP Server
Software\\Microsoft\\Windows NT\\CurrentVersion
System\\CurrentControlSet\\Control\\ContentIndex
System\\CurrentControlSet\\Control\\Terminal Server
System\\CurrentControlSet\\Control\\Terminal Server\\Userconfig
System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths\\

Value Name:  Machine

Value Type:  REG_MULTI_SZ
Value:  As defined in policy above

Note: Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the IAO this would not be a finding. Documentation should contain supporting information from the vendor's instructions.

Note:  Windows XP 64-Bit is based on Windows 2003.  On XP 64-bit systems apply the configuration for V0003339 and V0004443 as outlined in the Windows 2003 STIG."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Remotely accessible registry paths” as defined in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-156r1_chk'
  tag severity: 'high'
  tag gid: 'V-3339'
  tag rid: 'SV-6275r1_rule'
  tag gtitle: 'Remotely Accessible Registry Paths'
  tag fix_id: 'F-28869r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
