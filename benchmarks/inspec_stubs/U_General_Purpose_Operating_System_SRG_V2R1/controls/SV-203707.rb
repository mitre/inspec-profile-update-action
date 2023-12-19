control 'SV-203707' do
  title 'The operating system must provide a report generation capability that supports on-demand reporting requirements.'
  desc "The report generation capability must support on-demand reporting in order to facilitate the organization's ability to generate incident reports, as needed, to better handle larger-scale or more complex security incidents.

Report generation must be capable of generating on-demand (i.e., customizable, ad hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective."
  desc 'check', 'Verify the operating system provides a report generation capability that supports on-demand reporting requirements. If it does not, this is a finding.'
  desc 'fix', 'Ensure the operating system provides a report generation capability that supports on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3832r375068_chk'
  tag severity: 'medium'
  tag gid: 'V-203707'
  tag rid: 'SV-203707r379720_rule'
  tag stig_id: 'SRG-OS-000351-GPOS-00139'
  tag gtitle: 'SRG-OS-000351'
  tag fix_id: 'F-3832r375069_fix'
  tag 'documentable'
  tag legacy: ['V-57259', 'SV-71519']
  tag cci: ['CCI-001879']
  tag nist: ['AU-7 a']
end
