control 'SV-96905' do
  title 'The firewall protecting the MaaS360 server platform must be configured so that only DoD-approved ports, protocols, and services are enabled. (See the DoD Ports, Protocols, Services Management [PPSM] Category Assurance Levels [CAL] list for DoD-approved ports, protocols, and services.)'
  desc 'All ports, protocols, and services used on DoD networks must be approved and registered via the DoD PPSM process. This is to ensure that a risk assessment has been completed before a new port, protocol, or service is configured on a DoD network and has been approved by proper DoD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DoD network, which could be exploited by an adversary.

SFR ID: FMT_SMF.1.1(2) b'
  desc 'check', 'Ask the MaaS360 administrator for a list of ports, protocols, and services that have been configured on the host-based firewall of the MaaS360 server or generate the list by inspecting the firewall. Verify all allowed ports, protocols, and services are included on the DoD PPSM CAL list.

If any allowed ports, protocols, and services on the MaaS360 host-based firewall are not included on the DoD PPSM CAL list, this is a finding.'
  desc 'fix', 'Turn off any ports, protocols, and services on the MaaS360 host-based firewall that are not on the DoD PPSM CAL list.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81991r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82191'
  tag rid: 'SV-96905r1_rule'
  tag stig_id: 'M360-10-200300'
  tag gtitle: 'PP-MDM-331006'
  tag fix_id: 'F-89049r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
