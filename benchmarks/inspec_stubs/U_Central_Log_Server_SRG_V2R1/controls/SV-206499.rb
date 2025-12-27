control 'SV-206499' do
  title 'The Central Log Server must be configured to generate on-demand audit review and analysis reports.'
  desc "The report generation capability must support on-demand review and analysis to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Report generation must be capable of generating on-demand (i.e., customizable, ad hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective. 

Audit reduction and report generation capabilities do not always reside on the same information system or within the same organizational entities conducting auditing activities. The audit reduction capability can include, for example, modern data mining techniques with advanced data filters to identify anomalous behavior in log records. The report generation capability provided by the information system can generate customizable reports. Time ordering of log records can be a significant issue if the granularity of the timestamp in the record is insufficient.

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'Examine the configuration.

Verify the Central Log Server generates on-demand audit review and analysis reports.

If the Central Log Server is not configured to generate on-demand audit review and analysis reports, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to generate on-demand audit review and analysis reports.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6759r285738_chk'
  tag severity: 'low'
  tag gid: 'V-206499'
  tag rid: 'SV-206499r399904_rule'
  tag stig_id: 'SRG-APP-000366-AU-000220'
  tag gtitle: 'SRG-APP-000366'
  tag fix_id: 'F-6759r285739_fix'
  tag 'documentable'
  tag legacy: ['SV-95875', 'V-81161']
  tag cci: ['CCI-001878']
  tag nist: ['AU-7 a']
end
