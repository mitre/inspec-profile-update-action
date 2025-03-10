control 'SV-228878' do
  title 'The Palo Alto Networks security platform must, at a minimum, off-load threat and traffic log records onto a centralized log server in real time.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the Palo Alto Networks security platform is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time, which indicates that the time from event detection to off-loading is seconds or less. For the purposes of this requirement, the terms "real time" and "near-real time" are equivalent.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'To view a syslog server profile:
Go to Device >> Server Profiles >> Syslog

If there are no Syslog Server Profiles present, this is a finding.

Select each Syslog Server Profile; if no server is configured, this is a finding.

View the log-forwarding profile to determine which logs are forwarded to the syslog server.
Go to Objects >> Log forwarding

If no Log Forwarding Profile is present, this is a finding.

The  "Log Forwarding Profile" window has five columns.  If there are no Syslog Server Profiles present in the "Syslog" column for the Traffic Log Type, this is a finding.

If there are no Syslog Server Profiles present for each of the severity levels of the Threat Log Type, this is a finding.

Go to Device >> Log Settings >> System Logs
The list of Severity levels is displayed.

If any of the Severity levels does not have a configured Syslog Profile, this is a finding.

Go to Device >> Log Settings >> Config Logs

If the "Syslog field" is blank, this is a finding.'
  desc 'fix', 'To create a syslog server profile:
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

After you create the Server Profiles that define where to send the logs, log forwarding must be enabled. 
The way forwarding is enabled depends on the log type:
Traffic Logs-Enable forwarding of Traffic logs by creating a Log Forwarding Profile (Objects >> Log Forwarding) and adding it to the security policies to trigger the log forwarding. Only traffic that matches a specific rule within the security policy will be logged and forwarded.

Configure the log-forwarding profile to select the logs to be forwarded to syslog server.
Go to Objects >> Log forwarding
The "Log Forwarding Profile" window appears.  Note that it has five columns.
In the "Syslog" column, select the syslog server profile for forwarding threat logs to the configured server(s).
Select the "OK" button.

When the "Log Forwarding Profile" window disappears, the screen will show the configured log-forwarding profile.
Threat Logs-Enable forwarding of Threat logs by creating a Log Forwarding Profile (Objects >> Log Forwarding) that specifies which severity levels to forward and then adding it to the security policies for which to trigger the log forwarding. A Threat log entry will only be created (and therefore forwarded) if the associated traffic matches a Security Profile (Antivirus, Anti-spyware, Vulnerability, URL Filtering, File Blocking, Data Filtering, or DoS Protection).

Configure the log-forwarding profile to select the logs to be forwarded to syslog server.
Go to Objects >> Log forwarding
The "Log Forwarding Profile" window appears.  Note that it has five columns.
In the "Syslog" column, select the syslog server profile for forwarding threat logs to the configured server(s).
Select the "OK" button.

When the "Log Forwarding Profile" window disappears, the screen will show the configured log-forwarding profile.
For Traffic Logs and Threat Logs, use the log forwarding profile in the security rules.
Go to Policies >> Security Rule
Select the rule for which the log forwarding needs to be applied. Apply the security profiles to the rule.
Go to Actions >> Log forwarding
Select the log forwarding profile from drop-down list.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31113r513929_chk'
  tag severity: 'low'
  tag gid: 'V-228878'
  tag rid: 'SV-228878r831619_rule'
  tag stig_id: 'PANW-AG-000144'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-31090r513930_fix'
  tag 'documentable'
  tag legacy: ['V-62637', 'SV-77127']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
