control 'SV-251673' do
  title 'Splunk Enterprise must be configured to back up the log records repository at least every seven days onto a different system or system component other than the system or component being audited.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up log records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to ensure that in the event of a catastrophic system failure, the log records will be retained. 

This helps to ensure that a compromise of the information system being audited does not also result in a compromise of the log records.

This requirement only applies to applications that have a native backup capability for log records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', 'Interview the SA to verify that a process exists to back up the Splunk log data every seven days, using the underlying OS backup tools or another approved backup tool.

If a backup plan does not exist for the Splunk log data, this is a finding.'
  desc 'fix', 'Implement a backup plan for the Splunk log data, following the Splunk documentation on backing up indexed data. Use the underlying OS backup tools, or another approved backup tool.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55111r808253_chk'
  tag severity: 'low'
  tag gid: 'V-251673'
  tag rid: 'SV-251673r879582_rule'
  tag stig_id: 'SPLK-CL-000250'
  tag gtitle: 'SRG-APP-000125-AU-000300'
  tag fix_id: 'F-55065r808254_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
