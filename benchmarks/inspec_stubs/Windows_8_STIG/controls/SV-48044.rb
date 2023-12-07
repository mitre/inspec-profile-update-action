control 'SV-48044' do
  title 'Automatic logons must be disabled.'
  desc 'Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer.  Automatic logon with administrator privileges would give full access to an unauthorized individual.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: AutoAdminLogon

Type: REG_SZ
Value: 0

Severity Override:  If the "DefaultName" or "DefaultDomainName" in the same registry path contain an administrator account name and the "DefaultPassword" contains a value, this is a CAT I finding.)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".

Ensure no passwords are stored in the "DefaultPassword" registry value noted below.

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: DefaultPassword'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1145'
  tag rid: 'SV-48044r1_rule'
  tag stig_id: 'WN08-SO-000036'
  tag gtitle: 'Disable Automatic Logon'
  tag fix_id: 'F-41182r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If the DefaultName or DefaultDomainName in the same registry path contain an administrator account name and the DefaultPassword contains a value, this is a CAT I finding.'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
