control 'SV-254711' do
  title 'The firewall protecting the BlackBerry Enterprise Mobility Server (BEMS) must be configured so that only DOD-approved ports, protocols, and services are enabled.'
  desc 'All ports, protocols, and services used on DOD networks must be approved and registered via the DOD PPSM process. This is to ensure that a risk assessment has been completed before a new port, protocol, or service is configured on a DOD network and has been approved by proper DOD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DOD network, which could be exploited by an adversary.

See the DOD Ports, Protocols, Services Management (PPSM) Category Assurance Levels (CAL) list for DOD-approved ports, protocols, and services.'
  desc 'check', 'Ask the BEMS administrator for a list of ports, protocols, and services that have been configured on the host-based firewall of BEMS or generate the list by inspecting the firewall. Verify all allowed ports, protocols, and services are included on the DOD PPSM CAL list.

If any allowed ports, protocols, and services on the MDM host-based firewall are not included on the DOD PPSM CAL list, this is a finding.'
  desc 'fix', 'Turn off any ports, protocols, and services on the BEMS host-based firewall that are not on the DOD PPSM CAL list.'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58322r861856_chk'
  tag severity: 'medium'
  tag gid: 'V-254711'
  tag rid: 'SV-254711r879588_rule'
  tag stig_id: 'BEMS-03-004000'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-58268r861857_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
