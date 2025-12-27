control 'SV-213624' do
  title 'The EDB Postgres Advanced Server must provide an immediate real-time alert to appropriate support staff of all audit log failures.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

A failure of database auditing will result in either the database continuing to function without auditing or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review Postgres Enterprise Manager (PEM) alert settings, OS, or third-party logging software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Install PEM and configure audit failure event alerting as documented here: http://www.enterprisedb.com/docs/en/5.0/pemgetstarted/PEM_Getting_Started_Guide.1.28.html

An example for creating an alert that ensure the audit directory does not fill up is included below, using the thin client (browser) PEM interface. Refer also to the Supplemental Procedures document, supplied with this STIG.

Open the PEM web console in a browser

 - Log in
 - Click on the agent for the machine to be monitored
   - Select "Management | Probe Configuration"
   - Select "Disk Space" and set the check interval as you like
   - Select "Management | Alerting"
   - Name the definition "Audit Log Full"
   - Select Template "Disk Consumption Percentage"
   - Set Frequency, Comparison Operator, and Thresholds (1 minute, >, 
95/96/97 for example)
   - Enter the Mount Point for where the audit log is
   - Click Notification tab
   - Click Email all alerts
   - Click "Execute Script" on Monitored Server'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14846r495386_chk'
  tag severity: 'medium'
  tag gid: 'V-213624'
  tag rid: 'SV-213624r508024_rule'
  tag stig_id: 'PPS9-00-008100'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-14844r290185_fix'
  tag 'documentable'
  tag legacy: ['V-69001', 'SV-83605']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
