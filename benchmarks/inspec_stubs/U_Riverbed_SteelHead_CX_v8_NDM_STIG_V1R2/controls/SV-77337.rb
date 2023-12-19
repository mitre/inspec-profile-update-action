control 'SV-77337' do
  title 'Riverbed Optimization System (RiOS) must generate alerts that can be forwarded to the administrators and ISSO when local accounts are created.'
  desc 'An authorized insider or individual who maliciously creates a local account could gain immediate access from a remote location to privileged information on a critical security device. Sending an alert to the administrators and ISSO when this action occurs greatly reduces the risk that accounts will be surreptitiously created.

RiOS can be configured to send an SNMP trap to the SNMP server. It also sends a message to the Syslog and the local log. Either of these methods results in an alert that can be forwarded to authorized accounts.'
  desc 'check', 'Verify that RiOS captures an SNMP trap for user creation events that can be sent to the ISSO and designated administrators by the SNMP server.
Navigate to the device Management Console
Navigate to Configure >> System Settings >> Email

Verify that an SMTP Server is defined
Verify that an SMTP Port is defined
Verify that "Report Events via Email" is checked and that at least one email address is defined
Verify that "Report Failures via Email" is checked and that at least one email address is defined

If an email for the ISSO and the system administrator accounts are not defined, this is a finding.'
  desc 'fix', 'Configure RiOS to capture an SNMP trap for user creation events that can be sent to the ISSO and designated administrators by the SNMP server.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Email

Enter an SMTP Server name
Enter n SMTP Port number
Check "Report Events via Email" and enter at least one email address
Check "Report Failures via Email" and enter at least one email address'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63641r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62847'
  tag rid: 'SV-77337r2_rule'
  tag stig_id: 'RICX-DM-000011'
  tag gtitle: 'SRG-APP-000291-NDM-000275'
  tag fix_id: 'F-68765r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
