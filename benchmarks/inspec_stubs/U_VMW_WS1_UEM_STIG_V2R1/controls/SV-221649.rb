control 'SV-221649' do
  title 'The firewall protecting the Workspace ONE UEM server must be configured so that only DoD-approved ports, protocols, and services are enabled. (See the DoD Ports, Protocols, Services Management [PPSM] Category Assurance Levels [CAL] list for DoD-approved ports, protocols, and services).'
  desc 'All ports, protocols, and services used on DoD networks must be approved and registered via the DoD PPSM process. This is to ensure that a risk assessment has been completed before a new port, protocol, or service is configured on a DoD network and has been approved by proper DoD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DoD network, which could be exploited by an adversary.

'
  desc 'check', 'Ask the MDM administrator for a list of ports, protocols, and services that have been configured on the host-based firewall of the MDM server or generate the list by inspecting the firewall. Verify all allowed ports, protocols, and services are included on the DoD PPSM CAL list.

If any allowed ports, protocols, and services on the MDM host-based firewall are not included on the DoD PPSM CAL list, this is a finding.'
  desc 'fix', 'Turn off any ports, protocols, and services on the MDM host-based firewall that are not on the DoD PPSM CAL list.'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23364r416785_chk'
  tag severity: 'medium'
  tag gid: 'V-221649'
  tag rid: 'SV-221649r588007_rule'
  tag stig_id: 'VMW1-00-200030'
  tag gtitle: 'PP-MDM-431006'
  tag fix_id: 'F-23353r416786_fix'
  tag satisfies: ['SRG-APP-000142\n\nSFR ID: FMT_SMF.1.1(2) b']
  tag 'documentable'
  tag legacy: ['SV-111297', 'V-102341']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
