control 'SV-71517' do
  title 'The operating system must provide a report generation capability that supports on-demand audit review and analysis.'
  desc "The report generation capability must support on-demand review and analysis in order to facilitate the organization's ability to generate incident reports, as needed, to better handle larger-scale or more complex security incidents.

Report generation must be capable of generating on-demand (i.e., customizable, ad hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective."
  desc 'check', 'Verify the operating system provides a report generation capability that supports on-demand audit review and analysis. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide a report generation capability that supports on-demand audit review and analysis.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57257'
  tag rid: 'SV-71517r1_rule'
  tag stig_id: 'SRG-OS-000350-GPOS-00138'
  tag gtitle: 'SRG-OS-000350-GPOS-00138'
  tag fix_id: 'F-62191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001878']
  tag nist: ['AU-7 a']
end
