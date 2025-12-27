control 'SV-203651' do
  title 'The operating system must provide an audit reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports."
  desc 'check', 'Verify the operating system provides an audit reduction capability that supports on-demand reporting requirements. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide an audit reduction capability that supports on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3776r557198_chk'
  tag severity: 'medium'
  tag gid: 'V-203651'
  tag rid: 'SV-203651r557200_rule'
  tag stig_id: 'SRG-OS-000122-GPOS-00063'
  tag gtitle: 'SRG-OS-000122'
  tag fix_id: 'F-3776r557199_fix'
  tag 'documentable'
  tag legacy: ['V-56799', 'SV-71059']
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
