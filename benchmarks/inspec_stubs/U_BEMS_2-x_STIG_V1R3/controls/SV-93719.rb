control 'SV-93719' do
  title 'The firewall protecting the BlackBerry Enterprise Mobility Server (BEMS) must be configured so that only DoD-approved ports, protocols, and services are enabled. See the DoD Ports, Protocols, Services Management (PPSM) Category Assurance Levels (CAL) list for DoD-approved ports, protocols, and services.'
  desc 'All ports, protocols, and services used on DoD networks must be approved and registered via the DoD PPSM process. This is to ensure that a risk assessment has been completed before a new port, protocol, or service is configured on a DoD network and has been approved by proper DoD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DoD network, which could be exploited by an adversary.'
  desc 'check', 'Ask the BEMS administrator for a list of ports, protocols, and services that have been configured on the host-based firewall of BEMS or generate the list by inspecting the firewall. Verify all allowed ports, protocols, and services are included on the DoD PPSM CAL list.

If any allowed ports, protocols, and services on the MDM host-based firewall are not included on the DoD PPSM CAL list, this is a finding.'
  desc 'fix', 'Turn off any ports, protocols, and services on the BEMS host-based firewall that are not on the DoD PPSM CAL list.'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79013'
  tag rid: 'SV-93719r1_rule'
  tag stig_id: 'BEMS-00-004000'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-85763r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
