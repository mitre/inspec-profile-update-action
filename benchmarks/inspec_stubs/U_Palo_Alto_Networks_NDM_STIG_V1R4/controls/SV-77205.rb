control 'SV-77205' do
  title 'The Palo Alto Networks security platform must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly forwarding logs to a syslog server helps to assure, in the event of a catastrophic system failure, the audit records will be retained.

This requirement is met by configuring the Palo Alto Networks security platform to forward logs to a syslog server or a Panorama network security management server.  Note that the syslog server(s) must be backed up regularly, but that is not the focus of this requirement.'
  desc 'check', 'Check if there is a Syslog Server profile.
Go to Device >> Server Profiles >> Syslog
If there are no profiles listed in the "Servers" window, this is a finding.

Check if log forwarding is enabled for the Traffic Log and Threat Log.
Go to Objects >> Log forwarding
If the "Syslog" field does not list the Syslog Server profile for the Traffic Log, this is a finding.
 
If the "Syslog" field does not list the Syslog Server profile for all of the Severity levels of the Threat Log, this is a finding.

Check if log forwarding is enabled for the Configuration Log.
Go to Device >> Log Settings >> Config
In the "Log Settings - Config" pane.
If the "Syslog" field does not display the Syslog Server profile, this is a finding.

Check if log forwarding is enabled for the System Log.
Go to Device >> Log Settings >> System
The list of severity levels is displayed.
If the "Syslog Profile" field does not display the Syslog Server profile for each Severity level (except "informational"), this is a finding.'
  desc 'fix', 'Configuring the Palo Alto Networks security platform to forward logs to a syslog server depends on which log it is.
Create a Syslog Server profile:
Go to Device >> Server Profiles >> Syslog
Select "Add". 
In the "Syslog Server Profile", enter the name of the profile; select "Add".

In the "Servers" tab, enter the required information:
Name: Name of the syslog server
Server: Server IP address where the logs will be forwarded to
Port: Default port 514
Facility: Select from the drop down list
Select "OK".

Enable log forwarding for the Traffic Log and Threat Log. Configure the log-forwarding profile to select the logs to be forwarded to syslog server.
Go to Objects >> Log forwarding
Select "Add".
The "Log Forwarding Profile" window appears.  Note that it has five columns. 
Traffic Settings - in the "Syslog" column, select the "Syslog Server Profile".
Threat Settings - select the severity levels that will be sent to the syslog server; for each selected level, select the Syslog Server Profile.
Enable log forwarding for the Configuration Log.
Go to Device >> Log Settings >> Config
Select the "Edit" icon (the gear symbol in the upper-right corner of the pane)
In the "Log Settings - Config" window, in the "Syslog" drop-down box, select the configured server profile
Select "OK".

Enable log forwarding of System Log:
Go to Device >> Log Settings >> System
The list of severity levels is displayed. Select a Server Profile for each severity level to forward.  The "informational" severity level is optional; all others are mandatory.
Select each severity level in turn; with each selection, the "Log Systems - Setting" window will appear.
In the "Log Systems - Setting" window, in the "Syslog" drop-down box, select the configured server profile.
Select "OK".

For Traffic Logs and Threat Logs, use the log forwarding profile in the security rules:
Go to Policies >> Security
Select the rule for which the log forwarding needs to be applied. Apply the security profiles to the rule.
Go to "Actions" tab; in the "Log forwarding" field, select the log forwarding profile.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63521r1_chk'
  tag severity: 'low'
  tag gid: 'V-62715'
  tag rid: 'SV-77205r1_rule'
  tag stig_id: 'PANW-NM-000042'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-68635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
