control 'SV-206483' do
  title 'The Central Log Server must be configured to perform audit reduction that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'Examine the configuration.

Verify the system is configured to perform audit reduction that supports on-demand reporting requirements.

If the Central Log Server is not configured to perform audit reduction that supports on-demand reporting requirements, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform audit reduction that supports on-demand reporting requirements.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6743r285693_chk'
  tag severity: 'medium'
  tag gid: 'V-206483'
  tag rid: 'SV-206483r397612_rule'
  tag stig_id: 'SRG-APP-000181-AU-000200'
  tag gtitle: 'SRG-APP-000181'
  tag fix_id: 'F-6743r285694_fix'
  tag 'documentable'
  tag legacy: ['SV-95843', 'V-81129']
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
