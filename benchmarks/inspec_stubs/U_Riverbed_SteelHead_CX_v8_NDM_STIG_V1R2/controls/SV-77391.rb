control 'SV-77391' do
  title 'Riverbed Optimization System (RiOS) must generate an email alert of all log failure events requiring alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Verify that RiOS is configured to generate an immediate real-time alert for all audit failure events requiring real-time alerts.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Email

Verify that an SMTP Server is defined
Verify that an SMTP Port is defined
Verify that "Report Events via Email" is checked and that at least one email address is defined
Verify that "Report Failures via Email" is checked and that at least one email address is defined

If no email accounts are defined, this is a finding.'
  desc 'fix', 'Configure RiOS to generate an immediate real-time alert for all audit failure events requiring real-time alerts.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Email

Enter an SMTP Server name
Enter n SMTP Port number
Check "Report Events via Email" and enter at least one email address
Check "Report Failures via Email" and enter at least one email address'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62901'
  tag rid: 'SV-77391r1_rule'
  tag stig_id: 'RICX-DM-000053'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-68819r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
