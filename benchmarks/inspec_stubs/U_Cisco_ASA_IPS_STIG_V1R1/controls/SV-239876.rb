control 'SV-239876' do
  title 'The Cisco ASA must be configured to produce audit records containing information to establish the source of the event.'
  desc 'Associating the source of the event with detected events in the logs provides a means of investigating an attack or suspected attack.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.'
  desc 'check', 'Verify logging for connection events is enabled.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >>  Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy you want to view. The access control policy editor appears.

Step 3: Click the edit icon next to a rule to view. Verify that a logging option has been selected. Verify that the Syslog check box has been selected.
---------------------------------------------------
Verify logging for Intrusion events is enabled.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Intrusion Policy >> Intrusion Policy. The Intrusion Policy page appears.

Step 2: Click Advanced Setting. The Advanced Settings page appears.

Step 3: Verify that Syslog Alerting under External Responses is enabled. 

If the Cisco ASA Firepower is not configured to produce log records containing information to establish the source of the event, this is a finding.'
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

Step 4: in the Logging Hosts field, enter the remote access IP address you want to specify as logging host.

Step 5: Click Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43109r665939_chk'
  tag severity: 'medium'
  tag gid: 'V-239876'
  tag rid: 'SV-239876r665941_rule'
  tag stig_id: 'CASA-IP-000070'
  tag gtitle: 'SRG-NET-000077-IDPS-00062'
  tag fix_id: 'F-43068r665940_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
