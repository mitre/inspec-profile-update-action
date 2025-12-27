control 'SV-250746' do
  title 'The vCenter Administrator role must be secured by assignment to specific users authorized as vCenter Administrators.'
  desc "By default, vCenter Server grants full administrative rights to the local administrator's account, which can be accessed by domain administrators. Separation of duties dictates that full vCenter Administrative rights should be granted only to those administrators who are required to have it. This privilege should not be granted to any group whose membership is not strictly controlled. Administrative rights should be removed from the local Windows administrator account and be assigned to a special-purpose local vCenter Administrator account. This account should be used to create individual user accounts."
  desc 'check', 'Connect to the vCenter Server via the vSphere Client. Highlight the data center name and navigate to the Permissions tab. Observe the list of users and/or groups.

If any local administrator group permissions appear in the displayed list, this is a finding.

If a vCenter Administrator account (must be an ordinary user assigned the administrator role) does not appear in the displayed list, this is a finding.

If a vCenter Administrator account (must be an ordinary user assigned the administrator role) does appear in the displayed list, this is not a finding.'
  desc 'fix', 'Log into the Windows server as the Windows administrative user and create an ordinary user account that will be used to manage vCenter Server (example user: vAdmin). 

Ensure the ordinary user account (created above) does not belong to any local groups (example group: administrators). 

As the Windows administrative user, log into the vCenter Server (using the vSphere Client). Grant the role of administrator (global vCenter Server administrator) to the ordinary user account (created above). 

Log into the vCenter Server (using the vSphere Client) with the ordinary user account (created above) and verify that the user is able to perform all vCenter Server administrative tasks. 

As the Windows administrative user, log into the vCenter Server (using the vSphere Client). Delete the local administrator group from the permissions tab in the vSphere Client. Close the vSphere Client connection and attempt to reconnect to the Windows server as the Windows administrative user. The connection should now fail due to lack of administrator access/permissions.'
  impact 0.7
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54181r799926_chk'
  tag severity: 'high'
  tag gid: 'V-250746'
  tag rid: 'SV-250746r799928_rule'
  tag stig_id: 'VCENTER-000031'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54135r799927_fix'
  tag 'documentable'
  tag legacy: ['SV-51424', 'V-39566']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
