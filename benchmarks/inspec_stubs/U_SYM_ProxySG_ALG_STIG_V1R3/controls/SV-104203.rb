control 'SV-104203' do
  title 'Symantec ProxySG must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as network element components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify that the ProxySG is configured to log user web traffic for auditing that includes where the event occurred.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging. Verify that "Enable Access Logging" is checked.
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats," select the Default Log from step 3, and click "Edit/View".
5. Review the log format string and verify that at least the following variables are included:
  c-ip
  r-ip
  s-ip
  s-supplier-country

If Access Logging is not enabled and/or the specified log variables are not included, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log user web traffic for auditing that includes where the event occurred.

1. Log on to the Web Management Console.
2. Browse to "Configuration", click "Access Logging", check "Enable Access Logging", and click "Apply".
3. Browse to "Access Logging", click "General", and note which Default Log is indicated for the HTTP protocol ("main" by default).
4. Click "Formats", select the "Default Log" from step 3, and click "Edit/View".
5. Edit the log format string to include at least the following variables:
  c-ip
  r-ip
  s-ip
  s-supplier-country
6. Click OK >> Apply.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93435r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94249'
  tag rid: 'SV-104203r1_rule'
  tag stig_id: 'SYMP-AG-000170'
  tag gtitle: 'SRG-NET-000076-ALG-000045'
  tag fix_id: 'F-100365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
