control 'SV-243463' do
  title 'Local privileged groups (excluding Administrators) on the Windows PAW must be restricted to include no members.'
  desc 'A main security architectural construct of a PAW is to restrict access to the PAW from only specific privileged accounts designated for managing the high-value IT resources the PAW has been designated to manage. If unauthorized standard user accounts or unauthorized high-value administrative accounts are able to access a specific PAW, high-value IT resources and critical DoD information could be compromised.'
  desc 'check', 'Verify membership of local admin groups on the PAW are empty:

On the Windows PAW, verify there are no members in the following local privileged groups (excluding Administrators)*:

- Backup Operators (built-in)
- Cryptographic Operators
- Hyper-V Administrators
- Network Configuration Operators
- Power Users
- Remote Desktop Users
- Replicator

If the membership of the following admin groups is not empty, this is a finding: Backup Operators (built-in), Cryptographic Operators, Hyper-V Administrators, Network Configuration Operators, Power Users, Remote Desktop Users, and Replicator.

*Allowed exception: If a Hyper-V environment is used, the Hyper-V Administrators group may include members.'
  desc 'fix', 'Complete the following configuration procedures to restrict access to privileged accounts on the PAW (see the instructions for use of group policy to define membership, PAW Installation instructions in the Microsoft PAW paper).

Configure membership of all local privileged groups (except for "Administrators (built-in)" group) so it is empty*. This procedure applies to the following local privileged groups:

- Backup Operators (built-in)
- Hyper-V Administrators
- Network Configuration Operators
- Power Users
- Remote Desktop Users
- Replicator

Link the PAW group policy object (GPO) to the appropriate Tier devices Organizational Unit (OU).

*Allowed exception: If a Hyper-V environment is used, the Hyper-V Administrators group may include members.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46738r722958_chk'
  tag severity: 'medium'
  tag gid: 'V-243463'
  tag rid: 'SV-243463r722960_rule'
  tag stig_id: 'WPAW-00-002400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46695r722959_fix'
  tag 'documentable'
  tag legacy: ['V-78159', 'SV-92865']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
