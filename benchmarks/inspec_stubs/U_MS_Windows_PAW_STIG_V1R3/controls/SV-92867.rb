control 'SV-92867' do
  title 'Restricted remote administration must be enabled for high-value systems.'
  desc 'Restricted remote administration features, RestrictedAdmin mode, and Remote Credential Guard for Remote Desktop Protocol (RDP), are an additional safeguard against "pass the hash" attacks, where hackers attempt to gain higher administrative privileges from a single compromised machine. Restricted remote administration protects administrator accounts by ensuring that reusable credentials are not stored in memory on remote devices that could potentially be compromised. When restricted remote administration is implemented, the local RDP service tries to log on to the remote device using a network logon, so the user’s credentials are not sent across the network. Therefore, if the high-value IT resource is compromised, the credentials of the administrator connecting to the IT resource from the PAW are not compromised.'
  desc 'check', 'In the Registry Editor of the remote target system (high-value assets), verify the following registry key has a value of "0":

- HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa
- Name: DisableRestrictedAdmin
- Type: REG_DWORD
- Value: 0

If restricted remote administration has not been enabled on the target system, this is a finding.

In the Registry Editor of the PAW system, verify the following registry key has a value of "1":

HKLM\\Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation
Name: RestrictedRemoteAdministration
Type: REG_DWORD
Value: 1

If restricted remote administration has not been enabled on the PAW and is not enforced by policy, this is a finding.'
  desc 'fix', 'Enable RestrictedAdmin mode or Remote Credential Guard on high-value systems.

On target systems (high-value assets), configure the following registry value:

- HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa
- Name: DisableRestrictedAdmin
- Type: REG_DWORD 
- Value: 0

On PAW systems:

Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials Delegation "Restrict delegation of credentials to remote servers" to "Enabled".

Starting with v1607 of Windows 10, this setting also requires selection of an option for "Use the following restricted mode:" which includes the following:

Prefer Remote Credential Guard (v1703 - Restrict Credential Delegation)
Require Remote Credential Guard
Require Restricted Admin'
  impact 0.5
  ref 'DPMS Target Privileged Access Workstation (Windows)'
  tag check_id: 'C-77727r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78161'
  tag rid: 'SV-92867r1_rule'
  tag stig_id: 'WPAW-00-002500'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-84883r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
