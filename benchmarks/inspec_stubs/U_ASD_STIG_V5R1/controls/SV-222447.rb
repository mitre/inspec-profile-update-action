control 'SV-222447' do
  title 'The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.'
  desc 'HTTP header information is a critical component of data that is used when evaluating forensic activity.

Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following:

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify log locations for application session activity.

Open the log file that tracks user session activity.

Access the application as a regular user and identify the user session within the log files.

Perform several actions within the application in order to generate HTTP header traffic.

Review the logs to ensure the HTTP header information is recorded in the logs. Header information logged will vary based upon the application and environment. Examples of headers include but are not limited to:

User-Agent:
Referer:
X-Forwarded-For:
Date:
Expires:

If HTTP headers are not logged, this is a finding.'
  desc 'fix', 'Configure the web application and/or the web server to log HTTP headers.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24117r493249_chk'
  tag severity: 'medium'
  tag gid: 'V-222447'
  tag rid: 'SV-222447r508029_rule'
  tag stig_id: 'APSC-DV-000680'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24106r493250_fix'
  tag 'documentable'
  tag legacy: ['SV-83997', 'V-69375']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
