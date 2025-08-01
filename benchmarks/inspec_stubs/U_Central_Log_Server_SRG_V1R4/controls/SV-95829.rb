control 'SV-95829' do
  title 'The Central Log Server must be configured to retain the DoD-defined attributes of the log records sent by the devices and hosts.'
  desc 'Log records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records.

DoD has defined a list of information or attributes that must be included in the log record, including date, time, source, destination, module, severity level (category of information), etc. Other log record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server retains the DoD-defined attributes of the log records sent by the devices and hosts.

If the Central Log Server is not configured to retain the DoD-defined attributes of the log records sent by the devices and hosts, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to retain the DoD-defined attributes of the log records sent by the devices and hosts.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81115'
  tag rid: 'SV-95829r1_rule'
  tag stig_id: 'SRG-APP-000089-AU-000400'
  tag gtitle: 'SRG-APP-000089-AU-000400'
  tag fix_id: 'F-87887r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
