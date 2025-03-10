control 'SV-95877' do
  title 'The Central Log Server must be configured to generate reports that support on-demand reporting requirements.'
  desc "The report generation capability must support on-demand reporting to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents

The report generation capability provided by the application must be capable of generating on-demand (i.e., customizable, ad hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective. 

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand reporting requirements."
  desc 'check', 'Examine the configuration.

Verify the Central Log Server generates reports that support on-demand reporting requirements.

If the Central Log Server is not configured to generate reports that support on-demand reporting requirements, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to generate reports that support on-demand reporting requirements.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80827r1_chk'
  tag severity: 'low'
  tag gid: 'V-81163'
  tag rid: 'SV-95877r1_rule'
  tag stig_id: 'SRG-APP-000367-AU-000230'
  tag gtitle: 'SRG-APP-000367-AU-000230'
  tag fix_id: 'F-87939r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001879']
  tag nist: ['AU-7 a']
end
