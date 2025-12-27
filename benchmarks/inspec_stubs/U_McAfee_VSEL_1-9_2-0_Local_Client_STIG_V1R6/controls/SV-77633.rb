control 'SV-77633' do
  title 'A notification mechanism or process must be in place to notify Administrators of out of date DAT, detected malware and error codes.'
  desc 'Failure of anti-virus signature updates will eventually render the software to be useless in protecting the Linux system from malware. Administration notification for failed updates, via SMTP, will ensure timely remediation of errors causing DATs to not be updated.'
  desc 'check', 'The preferred method for notification is via SMTP alerts. 

Consult with the System Administrator to determine whether SMTP alerts are configured or whether some other notification mechanism (i.e., regular manual review of reports)is used.

If SMTP alerts are not configured, some other notification mechanism must be configured. 

For SMTP alert configuration in VSEL WEB Monitor:

From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "Configure", "Notifications".
Review the configured Notifications.
Verify the check box for "Item Detected" is selected. Verify check boxes for "Viruses", "Trojans", "Programs", "Jokes" and "Include alerts for on-demand tasks" are selected.
Verify the check box for "Out of date" is selected and "Alert for DAT files which are # days old" is configured to "7" or less.
Verify the check box for "Configuration changes" is selected.
Verify the check box for "System events" is selected. Verify check box for "Type" is selected and "Error" is selected from drop-down list.
Verify check box for "Code" is selected and "3000-3999" is entered in Code field.
Verify SMTP Settings are configured with valid email address(es) for System Administrators.


For SMTP alert configuration without the Web interface:

Access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "grep "notifications.virusDetected.active" nailsd.cfg"

If SMTP alert settings are not configured to send notifications to System Administrators, or some other mechanism is not used to provide this notification to System Administrators, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Configure", "Notifications", select the check box for "Item Detected".
Select check boxes for "Viruses", "Trojans", "Programs", "Jokes" and "Include alerts for on-demand tasks".
Select the check box for "Out of date" and configure "Alert for DAT files which are # days old" to "7" or less.
Select the check box for "Configuration changes".
Select the check box for "System events". Select check box for "Type" and select "Error" from drop-down list.
Select check box for "Code" and configured with "3000-3999" in Code field.
Configure the SMTP Settings with valid email address(es) for System Administrators.'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63895r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63143'
  tag rid: 'SV-77633r2_rule'
  tag stig_id: 'DTAVSEL-205'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-69061r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
