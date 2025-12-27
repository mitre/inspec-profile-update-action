control 'SV-32484' do
  title 'Unauthorized remotely accessible registry paths must not be configured.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require remote access to the registry.  This setting controls which registry paths are accessible from a remote computer.  These registry paths must be limited, as they could give unauthorized individuals access to the registry.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Network access: Remotely accessible registry paths" contains entries besides the following, this is a finding:

System\CurrentControlSet\Control\ProductOptions
System\CurrentControlSet\Control\Server Applications
Software\Microsoft\Windows NT\CurrentVersion

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\

Value Name:  Machine

Value Type:  REG_MULTI_SZ
Value:  As defined in policy above

Note:  Legitimate applications may add entries to this registry value.  If an application requires these entries to function properly and is documented with the ISSO, this would not be a finding.  Documentation should contain supporting information from the vendor's instructions.)
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Remotely accessible registry paths" with the following entries:

System\\CurrentControlSet\\Control\\ProductOptions 
System\\CurrentControlSet\\Control\\Server Applications 
Software\\Microsoft\\Windows NT\\CurrentVersion'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60987r2_chk'
  tag severity: 'high'
  tag gid: 'V-3339'
  tag rid: 'SV-32484r2_rule'
  tag gtitle: 'Remotely Accessible Registry Paths'
  tag fix_id: 'F-65717r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
