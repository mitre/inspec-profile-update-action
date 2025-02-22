control 'SV-95839' do
  title 'The Central Log Server must be configured to back up the log records repository at least every seven days onto a different system or system component other than the system or component being audited.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up log records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to ensure that in the event of a catastrophic system failure, the log records will be retained. 

This helps to ensure that a compromise of the information system being audited does not also result in a compromise of the log records.

This requirement only applies to applications that have a native backup capability for log records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server log records repository is backed up at least every seven days onto a different system or system component other than the system or component being audited.

If the Central Log Server is not configured to back up the log records repository at least every seven days onto a different system or system component other than the system or component being audited, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to back up the log records repository at least every seven days onto a different system or system component other than the system or component being audited.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80783r1_chk'
  tag severity: 'low'
  tag gid: 'V-81125'
  tag rid: 'SV-95839r1_rule'
  tag stig_id: 'SRG-APP-000125-AU-000300'
  tag gtitle: 'SRG-APP-000125-AU-000300'
  tag fix_id: 'F-87899r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
