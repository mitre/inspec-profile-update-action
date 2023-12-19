control 'SV-226319' do
  title 'Unauthorized remotely accessible registry paths must not be configured.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require remote access to the registry.  This setting controls which registry paths are accessible from a remote computer.  These registry paths must be limited, as they could give unauthorized individuals access to the registry.'
  desc 'check', "If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths\\

Value Name: Machine

Value Type: REG_MULTI_SZ
Value: see below

System\\CurrentControlSet\\Control\\ProductOptions 
System\\CurrentControlSet\\Control\\Server Applications 
Software\\Microsoft\\Windows NT\\CurrentVersion

Legitimate applications may add entries to this registry value.  If an application requires these entries to function properly and is documented with the ISSO, this would not be a finding. Documentation must contain supporting information from the vendor's instructions."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Remotely accessible registry paths" with the following entries:

System\\CurrentControlSet\\Control\\ProductOptions 
System\\CurrentControlSet\\Control\\Server Applications 
Software\\Microsoft\\Windows NT\\CurrentVersion'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28021r476801_chk'
  tag severity: 'high'
  tag gid: 'V-226319'
  tag rid: 'SV-226319r794546_rule'
  tag stig_id: 'WN12-SO-000056'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-28009r476802_fix'
  tag 'documentable'
  tag legacy: ['V-3339', 'SV-52883']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
