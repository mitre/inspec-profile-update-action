control 'SV-254255' do
  title 'Windows Server 2022 nonadministrative accounts or groups must only have print permissions on printer shares.'
  desc "Windows shares are a means by which files, folders, printers, and other resources can be published for network users to access. Improper configuration can permit access to devices and data beyond a user's need."
  desc 'check', 'Open "Printers & scanners" in "Settings".

If there are no printers configured, this is NA. (Exclude Microsoft Print to PDF and Microsoft XPS Document Writer, which do not support sharing.)

For each printer:

Select the printer and "Manage". 

Select "Printer Properties". 

Select the "Sharing" tab. 

If "Share this printer" is checked, select the "Security" tab.

If any standard user accounts or groups have permissions other than "Print", this is a finding.

The default is for the "Everyone" group to be given "Print" permission.

"All APPLICATION PACKAGES" and "CREATOR OWNER" are not standard user accounts.'
  desc 'fix', 'Configure the permissions on shared printers to restrict standard users to only have Print permissions.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57740r848579_chk'
  tag severity: 'low'
  tag gid: 'V-254255'
  tag rid: 'SV-254255r848581_rule'
  tag stig_id: 'WN22-00-000180'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-57691r848580_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
