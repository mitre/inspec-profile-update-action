control 'SV-77209' do
  title 'The Palo Alto Networks security platform must uniquely identify and authenticate organizational administrators (or processes acting on behalf of organizational administrators).'
  desc 'To assure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system.'
  desc 'check', 'Go to Device >> Administrators
View the list of configured Administrators.
If there are any accounts other than the emergency administration account than does not uniquely identify an individual, this is a finding.

If there is not an authentication profile for each account (with the exception of the emergency administration account), this is a finding.'
  desc 'fix', %q(Create a separate administrative account for each person who needs access to the administrative or reporting functions of the firewall.
Go to Device >> Administrators
Select "Add" (in the lower-left corner of the pane).
Complete the required information;
In the "Name" field, enter the name of the Administrator.
Note: That accounts must identify a single person; the only exception allowed is the emergency administration account.

In the "Authentication Profile" field, enter the name of the authentication profile that will be used to control that person's authentication process.
For the Role, select either "Dynamic" or "Role Based".
If selecting "Dynamic", then select the role assigned for this person; Administrators can be assigned one of these built-in roles: Superuser, Superuser (read-only), Device administrator, Device administrator (read-only), Virtual system administrator, and Virtual system administrator (read-only).
If "Role Based" is selected, then select one of the three pre-configured profiles (auditadmin, cryptoadmin, or securityadmin) or a custom profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63525r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62719'
  tag rid: 'SV-77209r1_rule'
  tag stig_id: 'PANW-NM-000047'
  tag gtitle: 'SRG-APP-000148-NDM-000246'
  tag fix_id: 'F-68639r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
