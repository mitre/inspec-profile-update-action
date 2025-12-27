control 'SV-93339' do
  title 'Tanium must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion.'
  desc 'check', 'Consult with the Tanium system administrator or database administrator to determine the volume on which the Tanium SQL databases are installed.

Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Sources.

If none exist to send Disk Free Space of the Tanium SQL Server, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when Disk Free Space of the Tanium SQL Server reaches below 25 percent.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Consult with the Tanium system administrator or database administrator to determine the volume on which the Tanium SQL databases are installed.

Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Interact".

Enter "Get Disk Free Space from all machines with Computer Name containing "[Your SQL Computer Name].

Press "Enter".

Select "Save this question" located under the Question box.

Enter a name (e.g., SQL Disk Free Space).

Select "Create Saved Question".

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Select "Create Connection".

In the Sources and Destination section select "Saved Question" from the drop-down menu.

Enter the "Saved Question Name" created above or select from the drop-down menu.

Select the "Computer Group" name from the drop-down menu.

Select the desired destination from the drop-down menu (must be a SIEM tool).

In the General Information section, provide a name and description.

Select "Create Connection" at bottom of the page.

Work with the SIEM administrator to configure an alert when Disk Free Space of the Tanium SQL Server reaches below 25 percent of maximum.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78203r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78633'
  tag rid: 'SV-93339r1_rule'
  tag stig_id: 'TANS-CN-000022'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-85369r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
