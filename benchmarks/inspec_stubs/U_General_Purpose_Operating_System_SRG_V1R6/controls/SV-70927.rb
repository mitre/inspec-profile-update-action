control 'SV-70927' do
  title 'The operating system must provide the capability to filter audit records for events of interest based upon all audit fields within audit records.'
  desc 'The ability to specify the event criteria that are of interest provides the individuals reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded.

Events of interest can be identified by the content of specific audit record fields, including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or selectable by specific information system component.

This requires operating systems to provide the capability to customize audit record reports based on all available criteria.'
  desc 'check', 'Verify the operating system provides the capability to filter audit records for events of interest based upon all audit fields within audit records. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide the capability to filter audit records for events of interest based upon all audit fields within audit records.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57237r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56667'
  tag rid: 'SV-70927r1_rule'
  tag stig_id: 'SRG-OS-000054-GPOS-00025'
  tag gtitle: 'SRG-OS-000054-GPOS-00025'
  tag fix_id: 'F-61563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
