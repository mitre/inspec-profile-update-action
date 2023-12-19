control 'SV-239874' do
  title 'The Cisco ASA must be configured to produce audit records containing information to establish when the events occurred.'
  desc 'Without establishing the time (date/time) an event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. Associating the date and time the event occurred with each event log entry provides a means of investigating an attack or identifying an improperly configured IDPS. 

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.'
  desc 'check', 'Verify logging for connection events is enabled.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy you want to view. The access control policy editor appears.

Step 3: Click the edit icon next to a rule to view. Verify a logging option has been selected, Verify the Syslog check box has been selected.
---------------------------------------------------
Verify logging for Intrusion events is enabled.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Intrusion Policy >> Intrusion Policy. The Intrusion Policy page appears.

Step 2: Click Advanced Setting. The Advanced Settings page appears.

Step 3: Verify that Syslog Alerting under External Responses is enabled. 

If the Cisco ASA is not configured to produce log records containing information to establish when the events occurred, this is a finding.'
  desc 'fix', 'Enable logging for connection events.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy you want to configure. The access control policy editor appears.

Step 3: Click the edit icon next to a rule to edit. Select a logging option either log at Beginning and End of Connection or log at End of Connection. Select the Syslog check box. 

Step 4: Click Save.
---------------------------------------------------
Enable logging for Intrusion events.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Intrusion Policy >> Intrusion Policy. The Intrusion Policy page appears.

Step 2: Click Advanced Setting. The Advanced Settings page appears.

Step 3: If Syslog Alerting under External Responses is enabled, click Edit. If the configuration is disabled, click Enabled, then click Edit. The Syslog Alerting page appears.

Step 4: In the Logging Hosts field, enter the remote access IP address you want to specify as logging host.

Step 5: Click Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43107r665933_chk'
  tag severity: 'medium'
  tag gid: 'V-239874'
  tag rid: 'SV-239874r665935_rule'
  tag stig_id: 'CASA-IP-000050'
  tag gtitle: 'SRG-NET-000075-IDPS-00060'
  tag fix_id: 'F-43066r665934_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
