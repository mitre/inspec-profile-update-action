control 'SV-222445' do
  title 'The application must provide audit record generation capability for session timeouts.'
  desc "When a user's session times out, it is important to be able to identify these events in the application logs.

Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following:

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Web-based applications will often utilize an application server that creates, manages, and logs session timeout information. It is acceptable for the application to delegate this requirement to the application server."
  desc 'check', 'Review the application documentation and interview the application administrator to identify log locations for application session activity.

Open the log file that tracks user session activity.

Access the application as a regular user and identify the user session within the log files.

Identify the session timeout threshold defined by the application.

Perform no action within the application in order to allow the session to timeout.

Once the session timeout threshold has been exceeded, verify the session has been terminated due to the timeout event and review the logs again to ensure the session timeout event was recorded in the logs.

If a web-based application delegates session timeout auditing to an application server, this is not a finding. 

If the session timeout event is not recorded in the logs, this is a finding.'
  desc 'fix', 'Configure the application to record session timeout events in the logs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24115r493243_chk'
  tag severity: 'medium'
  tag gid: 'V-222445'
  tag rid: 'SV-222445r879559_rule'
  tag stig_id: 'APSC-DV-000660'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24104r493244_fix'
  tag 'documentable'
  tag legacy: ['SV-83993', 'V-69371']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
