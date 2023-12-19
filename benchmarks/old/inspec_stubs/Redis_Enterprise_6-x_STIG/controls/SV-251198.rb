control 'SV-251198' do
  title 'Redis Enterprise DBMS must provide an immediate real-time alert to appropriate support staff of all audit log failures.'
  desc 'Redis Enterprise does not send immediate real-time alerts to support staff in the event of audit log failures; however, the host RHEL server can be configured to send such alerts using scripts or other third-party tools.

It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

A failure of database auditing will result in either the database continuing to function without auditing or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the OS or third-party logging software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Configure the system to provide an immediate real-time alert to appropriate support staff when an audit log failure occurs.

It is possible to create scripts or implement third-party tools to enable real-time alerting for audit log failures, depending on the underlying OS.

Additionally, it is recommended to enable the following alerts from within the Redis Enterprise AdminUI Console:

1. Log in to the AdminUI.
2. Navigate to settings >> alerts.
- Receive email alerts (with the appropriate email server settings configured under settings >> general)
- Node has sufficient disk space for AOF rewrite
- Multiple nodes are down - this may cause data loss'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54633r804782_chk'
  tag severity: 'medium'
  tag gid: 'V-251198'
  tag rid: 'SV-251198r855607_rule'
  tag stig_id: 'RD6X-00-005800'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-54587r804783_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
