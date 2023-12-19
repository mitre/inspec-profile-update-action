control 'SV-104209' do
  title 'Symantec ProxySG must generate audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify that the ProxySG is configured to log user web traffic for auditing, which includes information to establish the identity of any individual or process associated with the event.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Browse to "Access Logging", click "General", and note which "Default Log" is indicated for the HTTP protocol ("main" by default).
4. Click "Formats", select the Default Log from step 3 and click "Edit/View".
5. Review the log format string and verify that at least the "c-ip" and "cs-username" variables are included.

If Access Logging is not enabled and/or the specified log variables are not included, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log user web traffic for auditing that includes information to establish the identity of any individual or process associated with the event.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging. Check "Enable Access Logging" and click "Apply".
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the "HTTP" protocol ("main" by default).
4. Click "Formats," select the Default Log from step 3, and click "Edit/View".
5. Edit the log format string to include at least the "c-ip" and "cs-username" variables.
6. Click OK >> Apply.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93441r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94255'
  tag rid: 'SV-104209r1_rule'
  tag stig_id: 'SYMP-AG-000200'
  tag gtitle: 'SRG-NET-000079-ALG-000048'
  tag fix_id: 'F-100371r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
