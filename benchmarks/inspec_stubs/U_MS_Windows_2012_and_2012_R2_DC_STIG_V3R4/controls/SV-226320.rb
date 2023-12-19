control 'SV-226320' do
  title 'Unauthorized remotely accessible registry paths and sub-paths must not be configured.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require remote access to the registry.  This setting controls which registry paths and sub-paths are accessible from a remote computer.  These registry paths must be limited, as they could give unauthorized individuals access to the registry.'
  desc 'check', "If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths\\

Value Name: Machine

Value Type: REG_MULTI_SZ
Value: see below

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

Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the ISSO, this would not be a finding.  Documentation must contain supporting information from the vendor's instructions."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Remotely accessible registry paths and sub-paths" with the following entries:

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
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28022r476804_chk'
  tag severity: 'high'
  tag gid: 'V-226320'
  tag rid: 'SV-226320r794547_rule'
  tag stig_id: 'WN12-SO-000057'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-28010r476805_fix'
  tag 'documentable'
  tag legacy: ['SV-52931', 'V-4443']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
