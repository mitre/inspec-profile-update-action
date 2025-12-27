control 'SV-104205' do
  title 'Symantec ProxySG must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify that the ProxySG is configured to log user web traffic for auditing that includes the source of the event.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats", select the "Default Log" from step 3, and click "Edit/View".
5. Review the log format string and verify that at least the "c-ip" variable is included.

If Access Logging is not enabled and/or the specified log variables are not included, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log user web traffic for auditing that includes the source of the event.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check "Enable Access Logging" and click "Apply".
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats," select the Default Log from step 3, and click "Edit/View".
5. Edit the log format string to include at least the "c-ip" variable.
6. Click OK >> Apply.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93437r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94251'
  tag rid: 'SV-104205r1_rule'
  tag stig_id: 'SYMP-AG-000180'
  tag gtitle: 'SRG-NET-000077-ALG-000046'
  tag fix_id: 'F-100367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
