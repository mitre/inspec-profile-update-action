control 'SV-253791' do
  title 'The Tanium application must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'To ensure applications have a sufficient storage capacity in which to write the audit logs, applications must be able to allocate audit record storage capacity. 

The task of allocating audit record storage capacity is usually performed during initial installation of the application and is closely associated with the database administrator and system administrator roles. The database administrator or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer, and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.'
  desc 'check', 'Consult with the Tanium system administrator or database administrator to determine the volume on which the Tanium SQL databases are installed.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner.

3. Select "Connect". 

4. Review the configured Sources.

If none exist to send Disk Free Space of the Tanium SQL Server, this is a finding.

Work with the security information and event management (SIEM) administrator to determine if an alert is configured when Disk Free Space of the Tanium SQL Server reaches below 25%.

If no alert is configured, this is a finding.'
  desc 'fix', 'Consult with the Tanium system administrator or database administrator to determine the volume on which the Tanium SQL databases are installed.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Modules" in the top navigation banner.

3. Select "Interact".

4. Enter "Get Disk Free Space from all machines with Computer Name containing" [Your SQL Computer Name].

5. Press "Enter".

6. Select "Save this question" located under the Question box.

7. Enter a name (e.g., SQL Disk Free Space).

8. Select "Create Saved Question".

9. Click "Modules" in the top navigation banner.

10. Select "Connect".

11. Select "Create Connection".

12. In the "Configuration" section, select "Saved Question" from the Source drop-down menu.

13. Enter the "Saved Question Name" created above or select from the drop-down menu.

14. Select the "Computer Group" name from the drop-down menu.

15. Select the desired destination from the drop-down menu (must be a SIEM tool).

16. In the "General Information" section, provide a name and description.

17. Click "Save".

Work with the SIEM administrator to configure an alert when Disk Free Space of the Tanium SQL Server reaches below 25% of maximum.

Consult with the Tanium system administrator or database administrator to determine the volume on which the Tanium SQL databases are installed.

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application UI and log on with multifactor authentication.

2. Click "Modules" in the top navigation banner.

3. Select "Interact".

4. Enter "Get Disk Free Space from all machines with Computer Name containing" [Your SQL Computer Name].

5. Press "Enter".

6. Select "Save this question" located under the Question box.

7. Enter a name (e.g., SQL Disk Free Space).

8. Select "Create Saved Question".

9. Click "Modules" in the top navigation banner.

10. Select "Connect".

11. Select "Create Connection".

12. In the "Configuration" section, select "Saved Question" from the Source drop-down menu.

13. Enter the "Saved Question Name" created above or select from the drop-down menu.

14. Select the "Computer Group" name from the drop-down menu.

15. Select the desired destination from the drop-down menu (must be a SIEM tool).

16. In the "General Information" section, provide a name and description.

17. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57243r842399_chk'
  tag severity: 'medium'
  tag gid: 'V-253791'
  tag rid: 'SV-253791r850192_rule'
  tag stig_id: 'TANS-00-001305'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-57194r842400_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
