control 'SV-32257' do
  title 'Non-administrative user accounts or groups will only have print permissions of Printer Shares.'
  desc 'Improperly configured share permissions on printers can permit the addition of unauthorized print devices on the network.  Windows shares are a means by which files, folders, printers, and other resources can be published for network users to remotely access.  Regular users cannot create shares on their local machines; only Administrators and Power Users have that ability.'
  desc 'check', 'Open “Devices and Printers” in Control Panel.
If there are no locally-attached printers, then mark this as “Not Applicable.” 

Perform this check for each locally-attached printer: 
Right click on a locally-attached printer. 
Select “Printer Properties”. 
Select the “Sharing” tab. 
View whether “Share this printer” is checked. 

For any printers with “Share this printer” selected: 
Select the Security tab. 

If any non-administrative user accounts or groups have greater permissions than “Print”, then this is a finding.'
  desc 'fix', 'Configure the permissions on locally-shared printers to meet the minimum requirements.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32709r1_chk'
  tag severity: 'low'
  tag gid: 'V-1135'
  tag rid: 'SV-32257r1_rule'
  tag gtitle: 'Printer Share Permissions'
  tag fix_id: 'F-29047r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
