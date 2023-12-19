control 'SV-206495' do
  title 'The Central Log Server must be configured to perform on-demand sorting of log records for events of interest based on the content of organization-defined audit fields within log records.'
  desc 'The ability to sort the log records to better view events of interest provides the persons reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded.

This requires applications to be configured to sort log record reports based on organization-defined criteria.'
  desc 'check', 'Examine the configuration.

Verify the system is configured to perform on-demand sorting of log records for events of interest based on the content of organization-defined audit fields within log records.

If the Central Log Server is not configured to perform on-demand sorting of log records for events of interest based on the content of organization-defined audit fields within log records, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform on-demand sorting of log records for events of interest based on the content of organization-defined audit fields within log records.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6755r285726_chk'
  tag severity: 'low'
  tag gid: 'V-206495'
  tag rid: 'SV-206495r399892_rule'
  tag stig_id: 'SRG-APP-000362-AU-000170'
  tag gtitle: 'SRG-APP-000362'
  tag fix_id: 'F-6755r285727_fix'
  tag 'documentable'
  tag legacy: ['SV-95867', 'V-81153']
  tag cci: ['CCI-001886']
  tag nist: ['AU-7 (2)']
end
