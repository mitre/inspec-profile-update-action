control 'SV-16949' do
  title 'Printer share permissions are not configured as recommended.'
  desc 'Improperly configured share permissions on printers can permit the addition of unauthorized print devices on the network.  Windows shares are a means by which files, folders, printers, and other resources can be published for network users to remotely access.  Regular users cannot create shares on their local machines; only Administrators and Power Users have that ability.'
  desc 'check', '2008 - •Double click on  “Printers” in Control Panel

If there are no locally attached printers, then mark this as “Not Applicable.”

Perform this check for each locally attached printer:
•Right click on a locally-attached printer.
•Select Sharing from the drop-down menu.

Perform this check on each printer that has the “Shared” radio-button selected:
•Select the Security tab

The following table lists the Server 2008 default printer share security settings:

Account Assignment - Allow
Everyone - Print
CREATOR OWNER - Manage Documents
Administrator - Print, Manage Printers, Manage Documents
Administrators - Print, Manage Printers, Manage Documents

If any non administrative user accounts or groups have greater than “Print”, then this is a finding.'
  desc 'fix', 'Configure the permissions on locally shared printers to meet the minimum requirements.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-16642r1_chk'
  tag severity: 'low'
  tag gid: 'V-1135'
  tag rid: 'SV-16949r1_rule'
  tag gtitle: 'Printer Share Permissions'
  tag fix_id: 'F-88r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
