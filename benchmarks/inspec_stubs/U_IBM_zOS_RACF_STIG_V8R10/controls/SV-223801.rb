control 'SV-223801' do
  title 'IBM z/OS system administrator must develop a procedure to provide an audit reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports."
  desc 'check', 'Ask the system administrator for the procedure to provide an audit reduction capability that supports on-demand reporting requirements.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to provide an audit reduction capability that supports on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25474r515091_chk'
  tag severity: 'medium'
  tag gid: 'V-223801'
  tag rid: 'SV-223801r853627_rule'
  tag stig_id: 'RACF-OS-000470'
  tag gtitle: 'SRG-OS-000122-GPOS-00063'
  tag fix_id: 'F-25462r515092_fix'
  tag 'documentable'
  tag legacy: ['V-98309', 'SV-107413']
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
