control 'SV-25007' do
  title 'Printer share permissions must be restricted to Print for non administrators.'
  desc 'Improperly configured share permissions on printers can permit the addition of unauthorized print devices on the network.  Windows shares are a means by which files, folders, printers, and other resources can be published for network users to remotely access.'
  desc 'check', 'Open "Devices and Printers" in Control Panel.

If there are no locally attached printers, this is NA.

Perform this check for each locally attached printer:
Right-click on a locally attached printer.
Select "Printer Properties".
Select the "Sharing" tab.
View whether "Share this printer" is checked.

Perform this check on each printer that has the "Share this printer" selected:
Select the Security tab.

If any non-administrative user accounts or groups have greater than "Print", this is a finding.'
  desc 'fix', 'Configure the permissions on locally shared printers to ensure non administrators only have "Print".

Open "Devices and Printers" in Control Panel.

Right-click on a locally attached printer.
Select "Printer Properties".
Select the "Sharing" tab.

For each printer that has the "Share this printer" selected:
Select the Security tab.

Assign any non-administrative user accounts or groups "Print" permission only.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60783r3_chk'
  tag severity: 'low'
  tag gid: 'V-1135'
  tag rid: 'SV-25007r2_rule'
  tag gtitle: 'Printer Share Permissions'
  tag fix_id: 'F-65515r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
