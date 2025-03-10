control 'SV-228858' do
  title 'The Palo Alto Networks security platform must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'To view a syslog server profile:
Go to Device >> Server Profiles >> Syslog
If there are no Syslog Server Profiles present, this is a finding.

Select each Syslog Server Profile; if no server is configured, this is a finding.

View the log-forwarding profile to determine which logs are forwarded to the syslog server:
Go to Objects >> Log forwarding
If no Log Forwarding Profile is present, this is a finding.

The "Log Forwarding Profile" window has five columns.
If there are no Syslog Server Profiles present in the Syslog column for the Traffic Log Type, this is a finding.

If there are no Syslog Server Profiles present for each of the severity levels of the Threat Log Type, this is a finding.

Go to Device >> Log Settings >> System
The list of Severity levels is displayed.
If any of the Severity levels does not have a configured Syslog Profile, this is a finding.
Go to Device >> Log Settings >> Config
If the "Syslog" field is blank, this is a finding.

Note: Any one failure of a check results in a finding, but failing more than one still results in only one finding.  There cannot be multiple findings for a single requirement.'
  desc 'fix', 'Create a syslog server profile:
Go to Device >> Server Profiles >> Syslog
Select "Add". 
In the Syslog Server Profile, enter the name of the profile.
Select "Add".
In the "Servers" tab, enter the required information.
Name: Name of the syslog server
Server: Server IP address where the logs will be forwarded to
Port: Default port 514
Facility: Select from the drop-down list.
Select the "OK" button.

After the Server Profiles are created that define where to send the logs, enable log forwarding. 
The way forwarding is enabled depends on the log type:
Traffic Logs-Enable forwarding of Traffic logs by creating a Log Forwarding Profile (Objects >> Log Forwarding) and adding it to the security policies you want to trigger the log forwarding. Only traffic that matches a specific rule within the security policy will be logged and forwarded.
Configure the log-forwarding profile to select the logs to be forwarded to syslog server.
Go to Objects >> Log forwarding
The "Log Forwarding Profile" window appears.  Note that it has five columns.
In the "Syslog" column, select the syslog server profile for forwarding threat logs to the configured server(s).
Select the "OK" button.

When the "Log Forwarding Profile" window disappears, the screen will show the configured log-forwarding profile.
Threat Logs-Enable forwarding of Threat logs by creating a Log Forwarding Profile (Objects >> Log Forwarding) that specifies which severity levels you want to forward and then adding it to the security policies for which you want to trigger the log forwarding. A Threat log entry will only be created (and therefore forwarded) if the associated traffic matches a Security Profile (Antivirus, Anti-spyware, Vulnerability, URL Filtering, File Blocking, Data Filtering, or DoS Protection).
Configure the log-forwarding profile to select the logs to be forwarded to syslog server.
Go to Objects >> Log forwarding
The "Log Forwarding Profile" window appears.  Note that it has five columns.  In the "Syslog" column, select the syslog server profile for forwarding threat logs to the configured server(s).
Select the "OK" button.

When the Log Forwarding Profile window disappears, the screen will show the configured log-forwarding profile.
System Logs-Enable forwarding of System logs by specifying a Server Profile in the log settings configuration.
Go to Device >> Log Settings >> System
The list of severity levels is displayed.
You must select a Server Profile for each severity level you want to forward.  
Select each severity level in turn; with each selection, the Log "Systems - Setting" window will appear.  
In the "Log Systems - Setting" window, in the "Syslog" drop-down box, select the configured Server Profile.
Select the "OK" button.

Config Logs-Enable forwarding of Config logs by specifying a Server Profile in the log settings configuration:
Go to Device >> Log Settings >> Config
Select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Log Settings Config" window, in the "Syslog" drop-down box, select the configured Server Profile.
Select the "OK" button.

For Traffic Logs and Threat Logs, use the log forwarding profile in the security rules:
Go to Policies >> Security Rule
Select the rule for which the log forwarding needs to be applied. Apply the security profiles to the rule.
Go to Actions >> Log forwarding
Select the log forwarding profile from drop-down list.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31093r513869_chk'
  tag severity: 'medium'
  tag gid: 'V-228858'
  tag rid: 'SV-228858r557387_rule'
  tag stig_id: 'PANW-AG-000094'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-31070r513870_fix'
  tag 'documentable'
  tag legacy: ['V-62597', 'SV-77087']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
