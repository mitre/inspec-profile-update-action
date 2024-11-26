control 'SV-205560' do
  title 'The Mainframe Product must provide a report generation capability that supports on-demand reporting requirements.'
  desc "The report generation capability must support on-demand reporting in order to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents

The report generation capability provided by the application must be capable of generating on-demand (i.e., customizable, ad-hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective. 

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand reporting requirements."
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product report generation capability supports on-demand reporting. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product report generation capability to support on-demand reporting.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5826r299907_chk'
  tag severity: 'medium'
  tag gid: 'V-205560'
  tag rid: 'SV-205560r851324_rule'
  tag stig_id: 'SRG-APP-000367-MFP-000164'
  tag gtitle: 'SRG-APP-000367'
  tag fix_id: 'F-5826r299908_fix'
  tag 'documentable'
  tag legacy: ['SV-82771', 'V-68281']
  tag cci: ['CCI-001879']
  tag nist: ['AU-7 a']
end
