control 'SV-224384' do
  title 'The firewall protecting the BlackBerry UEM server platform must be configured so that only DoD-approved ports, protocols, and services are enabled. (See the DoD Ports, Protocols, Services Management [PPSM] Category Assurance Levels [CAL] list for DoD-approved ports, protocols, and services).'
  desc 'All ports, protocols, and services used on DoD networks must be approved and registered via the DoD PPSM process. This is to ensure that a risk assessment has been completed before a new port, protocol, or service is configured on a DoD network and has been approved by proper DoD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DoD network, which could be exploited by an adversary.

SFR ID: FMT_SMF.1.1(2) b / CM-7 b

'
  desc 'check', 'Ask the BlackBerry UEM administrator for a list of ports, protocols, and services that have been configured on the host-based firewall of the BlackBerry UEM server or generate the list by inspecting the firewall. Verify all allowed ports, protocols, and services are included on the DoD PPSM CAL list.

If any allowed ports, protocols, and services on the BlackBerry UEM host-based firewall are not included on the DoD PPSM CAL list, this is a finding.'
  desc 'fix', 'Turn off any ports, protocols, and services on the BlackBerry UEM host-based firewall that are not on the DoD PPSM CAL list.'
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26061r539052_chk'
  tag severity: 'medium'
  tag gid: 'V-224384'
  tag rid: 'SV-224384r604136_rule'
  tag stig_id: 'BUEM-00-200030'
  tag gtitle: 'PP-MDM-431006'
  tag fix_id: 'F-26049r539053_fix'
  tag satisfies: ['SRG-APP-000142']
  tag 'documentable'
  tag legacy: ['SV-111885', 'V-102923']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
