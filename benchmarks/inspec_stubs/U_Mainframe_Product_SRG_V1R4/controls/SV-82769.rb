control 'SV-82769' do
  title 'The Mainframe Product must provide a report generation capability that supports on-demand audit review and analysis.'
  desc "The report generation capability must support on-demand review and analysis in order to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Report generation must be capable of generating on-demand (i.e., customizable, ad-hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective. 

Audit reduction and report generation capabilities do not always reside on the same information system or within the same organizational entities conducting auditing activities. The audit reduction capability can include, for example, modern data mining techniques with advanced data filters to identify anomalous behavior in audit records. The report generation capability provided by the information system can generate customizable reports. Time ordering of audit records can be a significant issue if the granularity of the timestamp in the record is insufficient.

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product audit report generations support on-demand review and analysis. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit report generations to support on-demand review and analysis.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68279'
  tag rid: 'SV-82769r1_rule'
  tag stig_id: 'SRG-APP-000366-MFP-000163'
  tag gtitle: 'SRG-APP-000366-MFP-000163'
  tag fix_id: 'F-74393r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001878']
  tag nist: ['AU-7 a']
end
