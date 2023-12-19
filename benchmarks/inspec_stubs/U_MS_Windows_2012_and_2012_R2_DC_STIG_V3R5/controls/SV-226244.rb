control 'SV-226244' do
  title 'Nonadministrative user accounts or groups must only have print permissions on printer shares.'
  desc "Windows shares are a means by which files, folders, printers, and other resources can be published for network users to access.  Improper configuration can permit access to devices and data beyond a user's need."
  desc 'check', 'Open "Devices and Printers" in Control Panel or through Search.
If there are no printers configured, this is NA.(Exclude Microsoft Print to PDF and Microsoft XPS Document Writer, which do not support sharing.)

For each configured printer:
Right click on the printer. 
Select "Printer Properties". 
Select the "Sharing" tab. 
View whether "Share this printer" is checked. 

For any printers with "Share this printer" selected: 
Select the Security tab. 

If any standard user accounts or groups have permissions other than "Print", this is a finding.
Standard users will typically be given "Print" permission through the Everyone group.
"All APPLICATION PACKAGES" and "CREATOR OWNER" are not considered standard user accounts for this requirement.'
  desc 'fix', 'Configure the permissions on shared printers to restrict standard users to  only have Print permissions.  This is typically given through the Everyone group by default.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27946r476576_chk'
  tag severity: 'low'
  tag gid: 'V-226244'
  tag rid: 'SV-226244r794531_rule'
  tag stig_id: 'WN12-GE-000012'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27934r476577_fix'
  tag 'documentable'
  tag legacy: ['SV-52213', 'V-1135']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
