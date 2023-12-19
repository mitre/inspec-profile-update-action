control 'SV-243492' do
  title 'Systems must be monitored for remote desktop logons.'
  desc 'Remote Desktop activity for administration should be limited to specific administrators, and from limited management workstations.  Monitoring for any Remote Desktop logins outside of expected activity can alert on suspicious behavior and anomalous account usage that could be indicative of potential malicious credential reuse.'
  desc 'check', 'Verify Remote Desktop logins are being monitored.  Event monitoring may be implemented through various methods including log aggregation and the use of monitoring tools.

Monitor for the events listed below.  If these events are not monitored, this is a finding.

More advanced filtering is necessary to obtain the pertinent information than just looking for event IDs.
Search for the event IDs listed with the following additional attributes:
Logon Type = 10 (RemoteInteractive)
Authentication Package Name = Negotiate

Successful User Account Login (Subcategory: Logon)
4624 - An account was successfully logged on.'
  desc 'fix', %q(More advanced filtering is necessary to obtain the pertinent information than just looking for event IDs.
Search for the event IDs listed with the following additional attributes:
Logon Type = 10 (RemoteInteractive)
Authentication Package Name = Negotiate

Successful User Account Login (Subcategory: Logon)
4624 - An account was successfully logged on.

The "Remote Desktop Logon Detection" section of NSA's "Spotting the Adversary with Windows Event Log Monitoring" provides a sample query for filtering.
https://www.iad.gov/iad/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm.)
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46767r723509_chk'
  tag severity: 'medium'
  tag gid: 'V-243492'
  tag rid: 'SV-243492r723511_rule'
  tag stig_id: 'AD.AU.0003'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46724r723510_fix'
  tag 'documentable'
  tag legacy: ['V-43714', 'SV-56535']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
