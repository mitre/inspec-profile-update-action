control 'SV-224836' do
  title 'Non-administrative accounts or groups must only have print permissions on printer shares.'
  desc "Windows shares are a means by which files, folders, printers, and other resources can be published for network users to access. Improper configuration can permit access to devices and data beyond a user's need."
  desc 'check', 'Open "Devices and Printers".

If there are no printers configured, this is NA. (Exclude Microsoft Print to PDF and Microsoft XPS Document Writer, which do not support sharing.)

For each printer:

Right-click on the printer. 

Select "Printer Properties". 

Select the "Sharing" tab. 

If "Share this printer" is checked, select the "Security" tab.

If any standard user accounts or groups have permissions other than "Print", this is a finding.

The default is for the "Everyone" group to be given "Print" permission.

"All APPLICATION PACKAGES" and "CREATOR OWNER" are not standard user accounts.'
  desc 'fix', 'Configure the permissions on shared printers to restrict standard users to only have Print permissions.'
  impact 0.3
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26527r465410_chk'
  tag severity: 'low'
  tag gid: 'V-224836'
  tag rid: 'SV-224836r569186_rule'
  tag stig_id: 'WN16-00-000200'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-26515r465411_fix'
  tag 'documentable'
  tag legacy: ['V-73257', 'SV-87909']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
