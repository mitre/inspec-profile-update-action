control 'SV-204716' do
  title 'For application servers providing log record aggregation, the application server must compile log records from organization-defined information system components into a system-wide log trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the log trail.'
  desc 'Log generation and log records can be generated from various components within the application server. The list of logged events is the set of events for which logs are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records (e.g., logable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked).

The events occurring must be time-correlated in order to conduct accurate forensic analysis. In addition, the correlation must meet certain tolerance criteria. For instance, DoD may define that the time stamps of different logged events must not differ by any amount greater than ten seconds. It is also acceptable for the application server to utilize an external logging tool that provides this capability.'
  desc 'check', 'Review the application server log feature configuration to determine if the application server or an external logging tool in conjunction with the application server does compile log records from multiple components within the server into a system-wide log trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the log trail.

If the application server does not meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server or an external logging tool supporting the application server to compile log records from multiple components within the server into a system-wide log trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the log trail.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4836r282795_chk'
  tag severity: 'medium'
  tag gid: 'V-204716'
  tag rid: 'SV-204716r508029_rule'
  tag stig_id: 'SRG-APP-000086-AS-000048'
  tag gtitle: 'SRG-APP-000086'
  tag fix_id: 'F-4836r282796_fix'
  tag 'documentable'
  tag legacy: ['SV-46426', 'V-35139']
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
