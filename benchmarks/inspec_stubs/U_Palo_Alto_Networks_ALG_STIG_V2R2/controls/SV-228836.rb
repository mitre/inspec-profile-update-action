control 'SV-228836' do
  title 'The Palo Alto Networks security platform must log violations of security policies.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event. In addition to logging where sources of events such as IP addresses, processes, and node or device names, it is important to log the name or identifier of each specific policy or rule that is violated.

In the Palo Alto Networks security platform, traffic logs record information about each traffic flow, and threat logs record the threats or problems with the network traffic, such as virus or spyware detection.  Note that the antivirus, anti-spyware, and vulnerability protection profiles associated with each rule determine which threats are logged (locally or remotely).'
  desc 'check', 'Go to Policies >> Security
View the configured security policies.

For any Security Policy where the "Action" column shows "deny", view the "Options" column; if there are no icons in the column, this is a finding.

Note: The "Action" column and the "Option" column are usually near the right edge; it may be necessary to use the slide to view them.'
  desc 'fix', 'Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
In the "Actions" tab, select "Log At Session End".  This generates a traffic log entry for the end of a session and logs drop and deny entries.

Note: Traffic and Security Logs are required to be forwarded to syslog servers.

In the "Log Forwarding" field, select a configured log forwarding profile.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31071r513803_chk'
  tag severity: 'low'
  tag gid: 'V-228836'
  tag rid: 'SV-228836r557387_rule'
  tag stig_id: 'PANW-AG-000024'
  tag gtitle: 'SRG-NET-000077-ALG-000046'
  tag fix_id: 'F-31048r513804_fix'
  tag 'documentable'
  tag legacy: ['V-62555', 'SV-77045']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
