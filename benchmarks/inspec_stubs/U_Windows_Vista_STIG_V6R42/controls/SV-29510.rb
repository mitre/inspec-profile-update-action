control 'SV-29510' do
  title 'Printer share permissions are not configured as recommended.'
  desc 'Improperly configured share permissions on printers can permit the addition of unauthorized print devices on the network.  Windows shares are a means by which files, folders, printers, and other resources can be published for network users to remotely access.  Regular users cannot create shares on their local machines; only Administrators and Power Users have that ability.'
  desc 'check', 'Run Windows Explorer.
Select the Control Panel folder. (NT=Printers folder)
Select the Printers folder.

If there are no locally attached printers, then mark this as “Not Applicable.”

Perform this check for each locally attached printer:

Right click on a locally-attached printer.
Select Sharing from the drop-down menu.

Perform this check on each printer that has the “Shared” radio-button selected:

Select the Security tab

The following table lists the recommended printer share security settings (Allow Permission):

Users - Print
Administrators, System, Creator Owner - Print, Manage Printers, Manage Documents

If there are no shared local printers, then mark this as “Not Applicable.”
If the share permissions do not match the above table, then this is a finding.'
  desc 'fix', 'Configure the permissions on locally shared printers to meet the minimum requirements.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-80r1_chk'
  tag severity: 'low'
  tag gid: 'V-1135'
  tag rid: 'SV-29510r1_rule'
  tag gtitle: 'Printer Share Permissions'
  tag fix_id: 'F-88r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
