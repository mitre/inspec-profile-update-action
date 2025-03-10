control 'SV-82763' do
  title 'The Mainframe Product must provide an audit reduction capability that supports on-demand audit review and analysis.'
  desc "The ability to perform on-demand audit review and analysis, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Audit reduction is a technique used to reduce the volume of audit records in order to facilitate a manual review. Audit reduction does not alter original audit records. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage functions, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product audit reduction capability supports on-demand review and analysis. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit reduction capability to support on-demand review and analysis.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68273'
  tag rid: 'SV-82763r1_rule'
  tag stig_id: 'SRG-APP-000364-MFP-000160'
  tag gtitle: 'SRG-APP-000364-MFP-000160'
  tag fix_id: 'F-74387r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001875']
  tag nist: ['AU-7 a']
end
