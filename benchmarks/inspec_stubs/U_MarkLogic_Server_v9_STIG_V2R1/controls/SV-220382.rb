control 'SV-220382' do
  title 'MarkLogic Server must provide an immediate real-time alert to appropriate support staff of all audit failures.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

A failure of database auditing will result in either the database continuing to function without auditing or a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review OS scripts, or third-party monitoring software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Configure the system to provide an immediate real-time alert to appropriate support staff when a specified audit failure occurs by using OS scripts or a third-party tool for audit failure events alerting.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22097r401597_chk'
  tag severity: 'medium'
  tag gid: 'V-220382'
  tag rid: 'SV-220382r855487_rule'
  tag stig_id: 'ML09-00-007400'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-22086r401598_fix'
  tag 'documentable'
  tag legacy: ['SV-110113', 'V-101009']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
