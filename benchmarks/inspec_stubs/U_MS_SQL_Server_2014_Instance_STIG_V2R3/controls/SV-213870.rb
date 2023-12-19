control 'SV-213870' do
  title 'SQL Server or software monitoring SQL Server must provide an immediate real-time alert to appropriate support staff of all audit log failures.'
  desc "It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

As noted elsewhere in this document, SQL Server's Audit and/or Trace features can be used for auditing purposes. This requirement applies to both.

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

A failure of database auditing will result in either the database continuing to function without auditing or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less)."
  desc 'check', 'Review SQL Server settings, OS, or third-party logging software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Configure the system to provide immediate real-time alerts to appropriate support staff when an audit log failure occurs.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15089r855541_chk'
  tag severity: 'medium'
  tag gid: 'V-213870'
  tag rid: 'SV-213870r855542_rule'
  tag stig_id: 'SQL4-00-033500'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-15087r495396_fix'
  tag 'documentable'
  tag legacy: ['SV-82385', 'V-67895']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
