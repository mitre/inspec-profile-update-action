control 'SV-206593' do
  title 'The DBMS must provide an immediate real-time alert to appropriate support staff of all audit log failures.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

A failure of database auditing will result in either the database continuing to function without auditing or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review DBMS settings, OS, or third-party logging software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Configure the system to provide immediate real-time alerts to appropriate support staff when an audit log failure occurs.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6853r622557_chk'
  tag severity: 'medium'
  tag gid: 'V-206593'
  tag rid: 'SV-206593r617447_rule'
  tag stig_id: 'SRG-APP-000360-DB-000320'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-6853r531242_fix'
  tag 'documentable'
  tag legacy: ['SV-72489', 'V-58059']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
