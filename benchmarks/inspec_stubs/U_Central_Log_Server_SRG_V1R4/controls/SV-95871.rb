control 'SV-95871' do
  title 'The Central Log Server must be configured to perform audit reduction that supports on-demand audit review and analysis.'
  desc "The ability to perform on-demand audit review and analysis, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Audit reduction is a technique used to reduce the volume of log records to facilitate a manual review. Audit reduction does not alter original log records. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'Examine the configuration.

Verify the system performs audit reduction that supports on-demand audit review and analysis.

If the Central Log Server is not configured to perform audit reduction that supports on-demand audit review and analysis, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform audit reduction that supports on-demand audit review and analysis.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80819r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81157'
  tag rid: 'SV-95871r1_rule'
  tag stig_id: 'SRG-APP-000364-AU-000190'
  tag gtitle: 'SRG-APP-000364-AU-000190'
  tag fix_id: 'F-87931r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001875']
  tag nist: ['AU-7 a']
end
