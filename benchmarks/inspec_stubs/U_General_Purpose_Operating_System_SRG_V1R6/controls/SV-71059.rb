control 'SV-71059' do
  title 'The operating system must provide an audit reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports."
  desc 'check', 'Verify the operating system provides an audit reduction capability that supports on-demand reporting requirements. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide an audit reduction capability that supports on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57367r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56799'
  tag rid: 'SV-71059r1_rule'
  tag stig_id: 'SRG-OS-000122-GPOS-00063'
  tag gtitle: 'SRG-OS-000122-GPOS-00063'
  tag fix_id: 'F-61693r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
