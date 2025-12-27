control 'SV-205511' do
  title 'The Mainframe Product must provide an audit reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage functions, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product audit reduction capability supports on-demand reporting. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit reduction capability to support on-demand reporting.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5777r299766_chk'
  tag severity: 'medium'
  tag gid: 'V-205511'
  tag rid: 'SV-205511r851302_rule'
  tag stig_id: 'SRG-APP-000181-MFP-000161'
  tag gtitle: 'SRG-APP-000181'
  tag fix_id: 'F-5777r299767_fix'
  tag 'documentable'
  tag legacy: ['SV-82765', 'V-68275']
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
