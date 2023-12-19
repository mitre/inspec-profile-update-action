control 'SV-234353' do
  title 'The firewall protecting the UEM server platform must be configured so only DoD-approved ports, protocols, and services are enabled. (See the DoD Ports, Protocols, Services Management [PPSM] Category Assurance Levels [CAL] list for DoD-approved ports, protocols, and services).'
  desc 'All ports, protocols, and services used on DoD networks must be approved and registered via the DoD PPSM process. This is to ensure a risk assessment has been completed before a new port, protocol, or service is configured on a DoD network and has been approved by proper DoD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DoD network, which could be exploited by an adversary. 

Satisfies:FMT_SMF.1.1(2) Refinement b 
Reference:PP-MDM-431006'
  desc 'check', 'Verify the firewall protecting the UEM server platform is configured so that only DoD-approved ports, protocols, and services are enabled. (See the DoD PPSM CAL list for DoD-approved ports, protocols, and services).

If the firewall protecting the UEM server platform is not configured so that only DoD-approved ports, protocols, and services are enabled, this is a finding.'
  desc 'fix', 'Configure the firewall protecting the UEM server platform so that only DoD-approved ports, protocols, and services are enabled. (See the DoD PPSM CAL list for DoD-approved ports, protocols, and services).'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37538r614069_chk'
  tag severity: 'medium'
  tag gid: 'V-234353'
  tag rid: 'SV-234353r617355_rule'
  tag stig_id: 'SRG-APP-000142-UEM-000080'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-37503r614070_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
