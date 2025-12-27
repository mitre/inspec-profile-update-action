control 'SV-251666' do
  title 'Splunk Enterprise must be configured to retain the DoD-defined attributes of the log records sent by the devices and hosts.'
  desc 'Log records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records.

DoD has defined a list of information or attributes that must be included in the log record, including date, time, source, destination, module, severity level (category of information), etc. Other log record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.'
  desc 'check', 'Review the log records sent in Splunk Enterprise and verify that the log records retain the DoD-defined attributes.

If the log files do not retain the DoD-defined attributes, this is a finding.'
  desc 'fix', 'Configure Splunk Enterprise to retain the DoD-defined attributes of the log records sent by the devices and hosts.

Use Splunk Enterprise to modify the props.conf file to include the DoD-defined attributes.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55104r808232_chk'
  tag severity: 'medium'
  tag gid: 'V-251666'
  tag rid: 'SV-251666r808234_rule'
  tag stig_id: 'SPLK-CL-000130'
  tag gtitle: 'SRG-APP-000089-AU-000400'
  tag fix_id: 'F-55058r808233_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
