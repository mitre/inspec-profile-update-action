control 'SV-207458' do
  title 'The VMM must provide a report generation capability that supports on-demand audit review and analysis.'
  desc "The report generation capability must support on-demand review and analysis in order to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Report generation must be capable of generating on-demand (i.e., customizable, ad hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective."
  desc 'check', 'Verify the VMM provides a report generation capability that supports on-demand audit review and analysis.

If it does not, this is a finding.'
  desc 'fix', 'Ensure the VMM provides a report generation capability that supports on-demand audit review and analysis.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7715r365778_chk'
  tag severity: 'medium'
  tag gid: 'V-207458'
  tag rid: 'SV-207458r854629_rule'
  tag stig_id: 'SRG-OS-000350-VMM-001280'
  tag gtitle: 'SRG-OS-000350'
  tag fix_id: 'F-7715r365779_fix'
  tag 'documentable'
  tag legacy: ['V-57117', 'SV-71377']
  tag cci: ['CCI-001878']
  tag nist: ['AU-7 a']
end
