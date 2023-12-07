control 'SV-25259' do
  title 'Users must be prevented from connecting using Remote Desktop Services.'
  desc 'Allowing a remote desktop session to a workstation enables another avenue of access that could be exploited.  The system must be configured to prevent users from connecting to a computer using Remote Desktop Services.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fDenyTSConnections

Value Type:  REG_DWORD
Value:  1

If Remote Desktop Services for remote administration is necessary, enabling this would not be a finding. Restricted Admin mode must be used.  This must be document with the ISSO.
See Microsoft article KB2871997 for patches required to add this function to systems prior to Windows 8.1.

Restricted Admin mode for Remote Desktop Connections can be implemented for each session using a command line switch to start the Remote Desktop Client or through a group policy to enable it for all sessions.

The command line to do this is "mstsc /restrictedadmin".

To enable this with group policy, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation >> "Restrict delegation of credentials to remote servers" to "Enabled".'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Connections "Allow users to connect remotely using Remote Desktop Services" to "Disabled".

If Remote Desktop Services for remote administration is necessary, enabling this would not be a finding. Restricted Admin mode must be used.  This must be document with the ISSO.
See Microsoft article KB2871997 for patches required to add this function to systems prior to Windows 8.1.

Restricted Admin mode for Remote Desktop Connections can be implemented for each session using a command line switch to start the Remote Desktop Client or through a group policy to enable it for all sessions.

The command line to do this is "mstsc /restrictedadmin".

To enable this with group policy, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation >> "Restrict delegation of credentials to remote servers" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62233r3_chk'
  tag severity: 'medium'
  tag gid: 'V-14248'
  tag rid: 'SV-25259r2_rule'
  tag gtitle: 'TS/RDS - Remote User Connections'
  tag fix_id: 'F-67149r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
