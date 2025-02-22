control 'SV-207361' do
  title 'The VMM must support the capability to filter audit records for events of interest based upon all audit fields within audit records.'
  desc 'The ability to specify the event criteria that are of interest provides the individuals reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded. 

Events of interest can be identified by the content of specific audit record fields, including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations use all audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or selectable by specific VMM component.

This requires VMMs to provide the capability to customize audit record reports based on all available criteria.'
  desc 'check', 'Verify the VMM supports the capability to filter audit records for events of interest based upon all audit fields within audit records. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to support the capability to filter audit records for events of interest based upon all audit fields within audit records.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7618r365493_chk'
  tag severity: 'medium'
  tag gid: 'V-207361'
  tag rid: 'SV-207361r378643_rule'
  tag stig_id: 'SRG-OS-000054-VMM-000240'
  tag gtitle: 'SRG-OS-000054'
  tag fix_id: 'F-7618r365494_fix'
  tag 'documentable'
  tag legacy: ['SV-71159', 'V-56899']
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
