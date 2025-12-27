control 'SV-104199' do
  title 'Symantec ProxySG must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the gateway logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ProxySG is configured to log user web traffic for auditing that includes the event type.

1. Log on to the Web Management console.
2. Browse to "Configuration" and click "Access Logging. Verify that "Enable Access Logging" is checked.
3. Browse to "Access Logging", click "General," and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats," select the Default Log from step 3, and click "Edit/View".
5. Review the log format string and verify that at least the following variables are included:
  cs-method
  cs-protocol
  cs-uri-scheme
  cs-uri-path
  cs-uri-query
  sc-status
  s-action

If Access Logging is not enabled and/or the specified log variables are not included, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log user web traffic for auditing that includes the event type.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging. Check "Enable Access Logging" and click "Apply".
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats," select the Default Log from step 3, and click "Edit/View".
5. Edit the log format string to include at least the following variables:
  cs-method
  cs-protocol
  cs-uri-scheme
  cs-uri-path
  cs-uri-query
  sc-status
  s-action
6. Click OK >> Apply.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93431r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94245'
  tag rid: 'SV-104199r1_rule'
  tag stig_id: 'SYMP-AG-000150'
  tag gtitle: 'SRG-NET-000074-ALG-000043'
  tag fix_id: 'F-100361r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
