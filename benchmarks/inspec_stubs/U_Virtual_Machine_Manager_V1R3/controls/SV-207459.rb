control 'SV-207459' do
  title 'The VMM must provide a report generation capability that supports on-demand reporting requirements.'
  desc "The report generation capability must support on-demand reporting in order to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

Report generation must be capable of generating on-demand (i.e., customizable, ad hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective."
  desc 'check', 'Verify the VMM provides a report generation capability that supports on-demand reporting requirements.

If it does not, this is a finding.'
  desc 'fix', 'Ensure the VMM provides a report generation capability that supports on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7716r365781_chk'
  tag severity: 'medium'
  tag gid: 'V-207459'
  tag rid: 'SV-207459r854630_rule'
  tag stig_id: 'SRG-OS-000351-VMM-001290'
  tag gtitle: 'SRG-OS-000351'
  tag fix_id: 'F-7716r365782_fix'
  tag 'documentable'
  tag legacy: ['SV-71379', 'V-57119']
  tag cci: ['CCI-001879']
  tag nist: ['AU-7 a']
end
