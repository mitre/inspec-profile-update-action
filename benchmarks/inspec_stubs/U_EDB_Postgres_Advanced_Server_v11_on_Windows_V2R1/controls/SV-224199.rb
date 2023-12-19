control 'SV-224199' do
  title 'The EDB Postgres Advanced Server must provide an immediate real-time alert to appropriate support staff of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

The necessary monitoring and alerts may be implemented using features of EDB Postgres, the OS, third-party software, custom code, or a combination of these. The term "the system" is used to encompass all of these.'
  desc 'check', 'If Postgres Enterprise Manager (PEM) or another similar monitoring capability is not installed and configured to probe storage volume utilization of "<postgresql data directory>" and notify appropriate support staff upon storage volume utilization reaching capacity, this is a finding.

(The default path for the postgresql data directory is C:\\Program Files\\edb\\as<version>\\data, but this will vary according to local circumstances.)'
  desc 'fix', 'Install PEM (or similar tool) and configure a probe to monitor "<postgresql data directory>" and notify appropriate support staff upon storage volume utilization reaching capacity.

(The default path for the postgresql data directory is C:\\Program Files\\edb\\as<version>\\data, but this will vary according to local circumstances.)

Example steps for creating a probe are below, using the thin client (browser) PEM interface. Refer also to the Supplemental Procedures document, supplied with this STIG.

Open the PEM web console in a browser.
- Log in.
- Click on the agent for the machine to be monitored.
- Select "Management | Probe Configuration".
- Select "Disk Space" and set the check interval as you like.
- Select "Management | Alerting".
- Name the definition "Audit Log Full".
- Select Template "Disk Consumption Percentage".
- Set Frequency, Comparison Operator, and Thresholds (1 minute, >, 90/95/98 for example).
- Enter the Location for the audit log.
- Click Notification tab.
- Click Email all alerts.
- Click Add/Change to save, click "OK" to exit dialog box.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25872r495615_chk'
  tag severity: 'medium'
  tag gid: 'V-224199'
  tag rid: 'SV-224199r508023_rule'
  tag stig_id: 'EP11-00-008100'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-25860r495616_fix'
  tag 'documentable'
  tag legacy: ['V-100419', 'SV-109523']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
