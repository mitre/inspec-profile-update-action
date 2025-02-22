control 'SV-253729' do
  title 'MariaDB must provide an immediate real-time alert to appropriate support staff of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review MariaDB Server settings, OS, or third-party logging software settings to determine whether a real-time alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Configure the system to provide an immediate real-time alert to appropriate support staff when a specified audit failure occurs.

It is possible to create scripts or implement third-party tools to enable real-time alerting for audit failures in MariaDB.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57181r841710_chk'
  tag severity: 'medium'
  tag gid: 'V-253729'
  tag rid: 'SV-253729r841712_rule'
  tag stig_id: 'MADB-10-007500'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-57132r841711_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
