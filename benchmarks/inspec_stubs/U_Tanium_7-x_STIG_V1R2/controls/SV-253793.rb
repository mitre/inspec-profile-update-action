control 'SV-253793' do
  title 'The Tanium application must provide an immediate warning to the system administrator and information system security officer (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion.'
  desc 'check', 'Consult with the Tanium system administrator or database administrator to determine the volume on which the Tanium SQL databases are installed.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Modules" on the top navigation banner. 

3. Select "Connect".

4. Review the configured Connections under "Connections" section.

If none exist to send Disk Free Space of the Tanium SQL Server, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when Disk Free Space of the Tanium SQL Server reaches below 25%.

If no alert is configured, this is a finding.'
  desc 'fix', 'Consult with the Tanium system administrator or database administrator to determine the volume on which the Tanium SQL databases are installed.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Modules" on the top navigation banner.

3. Select "Interact".

4. Enter "Get Disk Free Space from all machines with Computer Name containing" [Your SQL Computer Name]. 

5. Click "Enter".

6. Confirm question.

7. Select "Save" to the right of the Question Results.

8. Enter a name (e.g., SQL Disk Free Space).

9. Click "Save".

10. Click "Modules" on the top navigation banner.

11. Select "Connect".

12. Select "Create Connection".

13. In the Configuration section, select "Saved Question" from the Source drop-down menu.

14. Enter the "Saved Question Name" created above or select from the drop-down menu.

15. Select the "Computer Group" name from the drop-down menu.

16. Select the desired destination from the drop-down menu (must be a SIEM tool).

17. In the "General Information" section, provide a name and description.

18. Click "Save".

Work with the SIEM administrator to configure an alert when Disk Free Space of the Tanium SQL Server reaches below 25% of maximum.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57245r842405_chk'
  tag severity: 'medium'
  tag gid: 'V-253793'
  tag rid: 'SV-253793r850194_rule'
  tag stig_id: 'TANS-00-001315'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-57196r842406_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
