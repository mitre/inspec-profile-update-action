control 'SV-239878' do
  title 'The Cisco ASA must be configured to log events based on policy access control rules, signatures, and anomaly analysis.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The IDPS must have the capability to capture and log detected security violations and potential security violations.'
  desc 'check', 'Verify that a Network Analysis policy exists.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy you want to view. The access control policy editor appears.

Step 3: Click Advanced Settings. The access control policy advanced settings page appears.

Step 4: Click the edit icon next to Network Analysis and Intrusion Policies. The Network Analysis and Intrusion Policies pop-up window appears.

Step 5: Click Network Analysis Policy List. The Network Analysis Policy List pop-up window appears.

Verify that a policy exists. By default, the system uses the Balanced Security and Connectivity network analysis policy.

Note: A network analysis policy governs how traffic is decoded and preprocessed so that it can be further evaluated for anomalous traffic that might signal an intrusion attempt. An intrusion policy uses intrusion and preprocessor rules (sometimes referred to collectively as intrusion rules) to examine the decoded packets for attacks based on patterns. Both network analysis and intrusion policies are invoked by a parent access control policy. As the system analyzes traffic, the network analysis phase occurs before and separately from the intrusion prevention phase. 
-------------------------------------------------
Verify logging for connection events is enabled.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy you want to view. The access control policy editor appears.

Step 3: Click the edit icon next to a rule to view. Verify that a logging option has been selected. Verify that the Syslog check box has been selected.
---------------------------------------------------
Verify logging for Intrusion events is enabled.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Intrusion Policy >> Intrusion Policy. The Intrusion Policy page appears.

Step 2: Click Advanced Settings. The Advanced Settings page appears.

Step 3: Verify that Syslog Alerting under External Responses is enabled.

If the Cisco ASA is not configured to log events based on policy access control rules, signatures, and anomaly analysis, this is a finding.'
  desc 'fix', 'Deploy a Network Analysis policy. 

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy you want to edit. The access control policy editor appears.

Step 3: Click Advanced Settings. The access control policy advanced settings page appears.

Step 4: Click the edit icon next to Network Analysis and Intrusion Policies. The Network Analysis and Intrusion Policies pop-up window appears.

Step 5: Enable the Balanced Security and Connectivity or a site-customized policy.
-------------------------------------------------
Enable logging for connection events.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy you want to configure. The access control policy editor appears.

Step 3: Click the edit icon next to a rule to edit. Select a logging option either log at Beginning and End of Connection or log at End of Connection. Select the Syslog check box.

Step 4: Click Save.
---------------------------------------
Enable logging for Intrusion events. 

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Intrusion Policy >> Intrusion Policy. The Intrusion Policy page appears.

Step 2: Click Advanced Settings. The Advanced Settings page appears.

Step 3: If Syslog Alerting under External Responses is enabled, click Edit. If the configuration is disabled, click Enabled, then click Edit. The Syslog Alerting page appears.

Step 4: in the Logging Hosts field, enter the remote access IP address you want to specify as logging host.

Step 5: Click Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43111r665945_chk'
  tag severity: 'medium'
  tag gid: 'V-239878'
  tag rid: 'SV-239878r665947_rule'
  tag stig_id: 'CASA-IP-000090'
  tag gtitle: 'SRG-NET-000113-IDPS-00013'
  tag fix_id: 'F-43070r665946_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
