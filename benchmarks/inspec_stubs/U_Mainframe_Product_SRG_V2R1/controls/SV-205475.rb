control 'SV-205475' do
  title 'The Mainframe Products must provide the capability to filter audit records for events of interest as defined in site security plan.'
  desc 'The ability to specify the event criteria that are of interest provides the persons reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded. 

Events of interest can be identified by the content of specific audit record fields including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or selectable by specific information system component. This requires applications to provide the capability to customize audit record reports based on organization-defined criteria.'
  desc 'check', "If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Refer to the site's auditing policies.

Verify the Mainframe Product filters audit record events of interest based on Site defined criteria. If it does not, this is a finding."
  desc 'fix', 'Configure the Mainframe Product to filter audit record events of interest based on Site defined criteria'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5741r299658_chk'
  tag severity: 'medium'
  tag gid: 'V-205475'
  tag rid: 'SV-205475r395814_rule'
  tag stig_id: 'SRG-APP-000115-MFP-000157'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-5741r299659_fix'
  tag 'documentable'
  tag legacy: ['SV-82761', 'V-68271']
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
