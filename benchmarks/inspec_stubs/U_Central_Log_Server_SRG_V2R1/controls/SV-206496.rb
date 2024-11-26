control 'SV-206496' do
  title 'The Central Log Server must be configured to perform on-demand searches of log records for events of interest based on the content of organization-defined audit fields within log records.'
  desc 'The ability to search the log records to better view events of interest provides the persons reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded.

This requires applications to provide the capability to search log record reports based on organization-defined criteria.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server performs on-demand searches of log records for events of interest based on the content of organization-defined audit fields within log records.

If the Central Log Server is not configured to perform on-demand searches of log records for events of interest based on the content of organization-defined audit fields within log records, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform on-demand searches of log records for events of interest based on the content of organization-defined audit fields within log records.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6756r285729_chk'
  tag severity: 'low'
  tag gid: 'V-206496'
  tag rid: 'SV-206496r399895_rule'
  tag stig_id: 'SRG-APP-000363-AU-000180'
  tag gtitle: 'SRG-APP-000363'
  tag fix_id: 'F-6756r285730_fix'
  tag 'documentable'
  tag legacy: ['SV-95869', 'V-81155']
  tag cci: ['CCI-001887']
  tag nist: ['AU-7 (2)']
end
