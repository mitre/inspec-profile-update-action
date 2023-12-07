control 'SV-32485' do
  title 'Unauthorized remotely accessible registry paths and sub-paths must not be configured.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require remote access to the registry.  This setting controls which registry paths and sub-paths are accessible from a remote computer.  These registry paths must be limited, as they could give unauthorized individuals access to the registry.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Network access: Remotely accessible registry paths and sub-paths" contains entries besides the following, this is a finding:

Software\Microsoft\OLAP Server
Software\Microsoft\Windows NT\CurrentVersion\Perflib
Software\Microsoft\Windows NT\CurrentVersion\Print
Software\Microsoft\Windows NT\CurrentVersion\Windows
System\CurrentControlSet\Control\ContentIndex
System\CurrentControlSet\Control\Print\Printers
System\CurrentControlSet\Control\Terminal Server
System\CurrentControlSet\Control\Terminal Server\UserConfig
System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
System\CurrentControlSet\Services\Eventlog
System\CurrentControlSet\Services\Sysmonlog

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE 
Registry Path:  \SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\

Value Name:  Machine

Value Type:  REG_MULTI_SZ
Value:  As defined in policy above

Note:  Legitimate applications may add entries to this registry value.  If an application requires these entries to function properly and is documented with the ISSO, this would not be a finding.  Documentation should contain supporting information from the vendor's instructions.)
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Remotely accessible registry paths and sub-paths" with the following entries:

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
System\\CurrentControlSet\\Services\\Sysmonlog'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60989r2_chk'
  tag severity: 'high'
  tag gid: 'V-4443'
  tag rid: 'SV-32485r2_rule'
  tag gtitle: 'Remotely Accessible Registry Paths and Sub-Paths'
  tag fix_id: 'F-65719r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
