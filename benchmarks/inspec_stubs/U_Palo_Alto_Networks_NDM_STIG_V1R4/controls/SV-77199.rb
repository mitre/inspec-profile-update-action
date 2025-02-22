control 'SV-77199' do
  title 'The Palo Alto Networks security platform must allow only the ISSM (or individuals or roles appointed by the ISSM) in the Audit Administrator (auditadmin) role, or in a custom role with full access to audit logs, or any account that has full access to audit logs.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

With the Palo Alto Networks security platform, Administrators can be assigned one of these built-in dynamic roles: Superuser, Superuser (read-only), Device administrator, Device administrator (read-only), Virtual system administrator, and Virtual system administrator (read-only) or they can be assigned one of the three pre-configured Role Based profiles (auditadmin, cryptoadmin, or securityadmin) or they can be assigned a custom profile.  The Audit Administrator (auditadmin) role is responsible for the regular review of the device's audit data.  The Superuser and Device administrator have full (both read and write) access to the device while the Virtual system administrator has full (both read and write) access to a specific virtual system instance."
  desc 'check', 'Obtain the list of personnel who are authorized full access to audit logs; these are the ISSM or individuals or roles appointed by the ISSM.
Go to Device >> Administrators
View each configured account in turn.
Note: The Role or Profile for each account.
If unauthorized personnel have a Superuser, Device administrator, or Virtual system administrator account, this is a finding.

If there are accounts Role of Custom role-based administrator, the following checks apply.
View the accounts with the Role of Custom role-based administrator and Profile of auditadmin; if unauthorized personnel are assigned this type of account, this is a finding.

View the accounts with the Role of Custom role-based administrator and a custom administrative profile; if this profile allows full access to audit logs and unauthorized personnel are assigned this type of account, this is a finding.'
  desc 'fix', %q(To create a separate administrative account for each person who needs full (read and write) access to the reporting functions of the firewall:
Go to Device >> Administrators
Select "Add" (in the lower-left corner of the pane).
Complete the required information - 
In the "Name" field, enter the name of the administrator.
Note: Accounts must identify a single person; the only exception allowed is the emergency administration account.

In the "Authentication Profile" field, enter the name of the authentication profile that will be used to control that person's authentication process.
For the Role, select either "Dynamic" or "Role Based". 
If selecting "Dynamic", then select the role assigned for this person: Superuser, Device administrator, or Virtual system administrator. 
If using the "Role Based" option, then select auditadmin or a custom profile with full access to audit logs. 
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63515r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62709'
  tag rid: 'SV-77199r1_rule'
  tag stig_id: 'PANW-NM-000023'
  tag gtitle: 'SRG-APP-000090-NDM-000222'
  tag fix_id: 'F-68629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
