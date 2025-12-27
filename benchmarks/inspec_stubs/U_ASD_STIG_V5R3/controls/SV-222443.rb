control 'SV-222443' do
  title 'The application must provide audit record generation capability for the renewal of session IDs.'
  desc "Application design sometimes requires the renewal of session IDs in order to continue approved user access to the application.

Session renewal is done on a case by case basis under circumstances defined by the application architecture. The following are some examples of when session renewal must be done; whenever there is a change in user privilege such as transitioning from a user to an admin role or when a user changes from an anonymous user to an authenticated user or when a user's permissions have changed.

For these types of critical application functionalities, the previous session ID needs to be destroyed or otherwise invalidated and a new session ID must be created.

It is important to log when session IDs are renewed for forensic purposes.

Web based applications will often utilize an application server that creates, manages and logs session IDs.  It is acceptable for the application to delegate this requirement to the application server."
  desc 'check', "Interview the system admin and review the application documentation.

Identify any web pages or application functionality where a user's privileges or permissions will change. This is most likely to occur during the authentication stages.

Evaluate the log/audit output by opening the log files and observing changes to the logs.

Create a new user session by accessing the application.

Review the logs and save the relevant session creation event recorded.

Utilize the application pages that provide privilege escalation.

Escalate privileges by authenticating as a privileged user.

Review the logs and determine if new session information is created and being used.

If a web-based application delegates session ID renewals to an application server, this is not a finding. 

If the application is not configured to log session ID renewal events this is a finding."
  desc 'fix', 'Design or reconfigure the application to log session renewal events on those application events that provide changes in the users privileges or permissions to the application.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24113r493237_chk'
  tag severity: 'medium'
  tag gid: 'V-222443'
  tag rid: 'SV-222443r879559_rule'
  tag stig_id: 'APSC-DV-000640'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24102r493238_fix'
  tag 'documentable'
  tag legacy: ['SV-83989', 'V-69367']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
