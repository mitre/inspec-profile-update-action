control 'SV-56534' do
  title 'Systems must be monitored for attempts to use local accounts to log on remotely from other systems.'
  desc 'Monitoring for the use of local accounts to log on remotely from other systems may indicate attempted lateral movement in a Pass-the-Hash attack.'
  desc 'check', 'Verify attempts to use local accounts to log on remotely from other systems are being monitored.  Event monitoring may be implemented through various methods including log aggregation and the use of monitoring tools.

Monitor for the events listed below.  If these events are not monitored, this is a finding.

More advanced filtering is necessary to obtain the pertinent information than just looking for event IDs.
Search for the event IDs listed with the following additional attributes:
Logon Type = 3 (Network)
Authentication Package Name = NTLM
Not a domain logon and not the ANONYMOUS LOGON account

Successful User Account Login (Subcategory: Logon)
4624 - An account was successfully logged on.
Failed User Account Login (Subcategory: Logon)
4625 - An account failed to log on.'
  desc 'fix', %q(Monitor for attempts to use local accounts to log on remotely from other systems.  Event monitoring may be implemented through various methods including log aggregation and the use of monitoring tools.

Monitor for the events listed below.

More advanced filtering is necessary to obtain the pertinent information than just looking for event IDs.
Search for the event IDs listed with the following additional attributes:
Logon Type = 3 (Network)
Authentication Package Name = NTLM
Not a domain logon and not the ANONYMOUS LOGON account

Successful User Account Login (Subcategory: Logon)
4624 - An account was successfully logged on.
Failed User Account Login (Subcategory: Logon)
4625 - An account failed to log on.

The "Pass the Hash Detection" section of NSA's "Spotting the Adversary with Windows Event Log Monitoring" provides a sample query for filtering.
https://www.iad.gov/iad/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm.)
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-66425r1_chk'
  tag severity: 'medium'
  tag gid: 'V-43713'
  tag rid: 'SV-56534r4_rule'
  tag stig_id: 'AD.AU.0002'
  tag gtitle: 'AD.AU.0002'
  tag fix_id: 'F-71813r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
