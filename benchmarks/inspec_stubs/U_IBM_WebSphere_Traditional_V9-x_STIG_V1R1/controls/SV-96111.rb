control 'SV-96111' do
  title 'The WebSphere Application Server must remove organization-defined software components after updated versions have been installed.'
  desc 'By default, when updating WebSphere application server, the older version of binaries are saved in case a "roll back" is necessary. Not keeping the older version makes it more difficult for attackers to "revert" back to the older version.'
  desc 'check', 'Review System Security Plan and system documentation to locate the "IBM InstallationManager" folder.

Default locations are:
UNIX:
/opt/InstallationManager

Windows:
C:\\Program Files\\InstallationManager

UNIX:
<IMHOME>/eclipse/tools/imcl -c

Select "P" preferences.
Select "3" Files for rollback.

Windows:
<IMHOME>\\eclipse\\tools\\imcl.exe -c

Select "P" preferences.
Select "3" Files for rollback.

If "Save files for rollback" is checked, this is a finding.'
  desc 'fix', 'Review System Security Plan and system documentation to locate the "IBM InstallationManager" folder.

Default locations are:
UNIX:
/opt/InstallationManager

Windows:
C:\\Program Files\\InstallationManager

UNIX:
<IMHOME>/eclipse/tools/imcl -c

Select "P" preferences. 
Select "3" Files for rollback.
Enter "1" to deselect.
Enter "A" for apply.
Enter "R" to return to Main Menu.

Windows:
<IMHOME>\\eclipse\\tools\\imcl.exe -c

Select "P" preferences.
Select "3" Files for rollback.
Enter "1" to deselect.
Enter "A" for apply.
Enter "R" to return to Main Menu.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81107r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81397'
  tag rid: 'SV-96111r1_rule'
  tag stig_id: 'WBSP-AS-001740'
  tag gtitle: 'SRG-APP-000454-AS-000268'
  tag fix_id: 'F-88183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
