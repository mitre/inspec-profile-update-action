control 'SV-104207' do
  title 'Symantec ProxySG must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the network after the event occurred). They also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify that the ProxySG is configured to log user web traffic for auditing that includes information about the outcome of the event.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats", select the Default Log from step 3, and click "Edit/View".
5. Review the log format string and verify that at least the following variables are included:
  s-action
  rs-response-line
  rs-status
  sc-status
  x-exception-reason
  duration

If Access Logging is not enabled and/or the specified log variables are not included, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log user web traffic for auditing that includes information about the outcome of the event.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check "Enable Access Logging" and click "Apply".
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats", select the Default Log from step 3, and click "Edit/View".
5. Edit the log format string to include at least the following variables:
  s-action
  rs-response-line
  rs-status
  sc-status
  x-exception-reason
 duration
6. Click OK >> Apply.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93439r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94253'
  tag rid: 'SV-104207r1_rule'
  tag stig_id: 'SYMP-AG-000190'
  tag gtitle: 'SRG-NET-000078-ALG-000047'
  tag fix_id: 'F-100369r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
