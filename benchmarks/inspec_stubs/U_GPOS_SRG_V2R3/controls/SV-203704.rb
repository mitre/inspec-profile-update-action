control 'SV-203704' do
  title 'The operating system must provide an audit reduction capability that supports on-demand audit review and analysis.'
  desc "The ability to perform on-demand audit review and analysis, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports, as needed, to better handle larger-scale or more complex security incidents.

Audit reduction is a technique used to reduce the volume of audit records in order to facilitate a manual review. Audit reduction does not alter original audit records. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports."
  desc 'check', 'Verify the operating system provides an audit reduction capability that supports on-demand audit review and analysis. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide an audit reduction capability that supports on-demand audit review and analysis.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3829r375059_chk'
  tag severity: 'medium'
  tag gid: 'V-203704'
  tag rid: 'SV-203704r379711_rule'
  tag stig_id: 'SRG-OS-000348-GPOS-00136'
  tag gtitle: 'SRG-OS-000348'
  tag fix_id: 'F-3829r375060_fix'
  tag 'documentable'
  tag legacy: ['V-57253', 'SV-71513']
  tag cci: ['CCI-001875']
  tag nist: ['AU-7 a']
end
