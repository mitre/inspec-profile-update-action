control 'SV-233105' do
  title 'The container platform must provide an audit reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'Review the container platform configuration to determine if the container platform is configured to provide an audit reduction capability that supports on-demand reporting requirements. 

If the container platform is not configured to support on-demand reporting requirements, this is a finding.'
  desc 'fix', 'Configure the container platform to support on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36041r601738_chk'
  tag severity: 'medium'
  tag gid: 'V-233105'
  tag rid: 'SV-233105r879618_rule'
  tag stig_id: 'SRG-APP-000181-CTR-000485'
  tag gtitle: 'SRG-APP-000181'
  tag fix_id: 'F-36009r600803_fix'
  tag 'documentable'
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
