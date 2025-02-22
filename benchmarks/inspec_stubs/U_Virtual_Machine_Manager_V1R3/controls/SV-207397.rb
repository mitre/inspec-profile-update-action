control 'SV-207397' do
  title 'The VMM must support an audit reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports."
  desc 'check', 'Verify the VMM supports an audit reduction capability that supports on-demand reporting requirements.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to support an audit reduction capability that supports on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7654r365601_chk'
  tag severity: 'medium'
  tag gid: 'V-207397'
  tag rid: 'SV-207397r854606_rule'
  tag stig_id: 'SRG-OS-000122-VMM-000610'
  tag gtitle: 'SRG-OS-000122'
  tag fix_id: 'F-7654r365602_fix'
  tag 'documentable'
  tag legacy: ['SV-71255', 'V-56995']
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
