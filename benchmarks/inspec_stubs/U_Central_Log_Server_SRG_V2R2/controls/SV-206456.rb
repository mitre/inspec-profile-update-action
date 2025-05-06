control 'SV-206456' do
  title 'The Central Log Server must be configured to perform on-demand filtering of the log records for events of interest based on organization-defined criteria.'
  desc 'The ability to specify the event criteria that are of interest provides the persons reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded. 

Events of interest can be identified by the content of specific log record fields including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required; for example, locations selectable by general networking location (e.g., by network or subnetwork) or by specific information system component. This requires applications to be configured to customize log record reports based on organization-defined criteria.

Summary reports provide oversight for security devices, helping to identify when a device is not detecting or blocking to the extent one would expect. A simple “top 10” list of what was detected and blocked, with a count by severity, can help prioritize security responses. Operational reports detailing the source hosts for any given malware can then direct remediation responses.'
  desc 'check', 'Examine the configuration.

Verify the system is configured to perform on-demand filtering of the log records for events of interest based on organization-defined criteria.

If the Central Log Server is not configured to perform on-demand filtering of the log records for events of interest based on organization-defined criteria, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform on-demand filtering of the log records for events of interest based on organization-defined criteria.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6716r285612_chk'
  tag severity: 'low'
  tag gid: 'V-206456'
  tag rid: 'SV-206456r395814_rule'
  tag stig_id: 'SRG-APP-000115-AU-000160'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-6716r285613_fix'
  tag 'documentable'
  tag legacy: ['SV-95835', 'V-81121']
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
