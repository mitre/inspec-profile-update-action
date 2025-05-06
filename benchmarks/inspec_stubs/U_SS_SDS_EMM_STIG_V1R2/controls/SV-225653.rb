control 'SV-225653' do
  title 'The firewall protecting the Samsung SDS EMM platform must be configured so that only DoD-approved ports, protocols, and services are enabled. See the DoD Ports, Protocols, Services Management [PPSM] Category Assurance Levels [CAL] list for DoD-approved ports, protocols, and services.'
  desc 'All ports, protocols, and services used on DoD networks must be approved and registered via the DoD PPSM process. This is to ensure that a risk assessment has been completed before a new port, protocol, or service is configured on a DoD network and has been approved by proper DoD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DoD network, which could be exploited by an adversary.

SFR ID: FMT_SMF.1.1(2) b / CM-7 b

'
  desc 'check', 'Ask the MDM administrator for a list of ports, protocols, and services that have been configured on the host-based firewall of the Samsung SDS EMM or generate the list by inspecting the firewall. Verify all allowed ports, protocols, and services are included on the DoD PPSM CAL list.

If any allowed ports, protocols, and services on the MDM host-based firewall are not included on the DoD PPSM CAL list, this is a finding.'
  desc 'fix', 'Turn off any ports, protocols, and services on the MDM host-based firewall that are not on the DoD PPSM CAL list.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27354r560981_chk'
  tag severity: 'medium'
  tag gid: 'V-225653'
  tag rid: 'SV-225653r588007_rule'
  tag stig_id: 'SSDS-00-200030'
  tag gtitle: 'PP-MDM-431006'
  tag fix_id: 'F-27342r560982_fix'
  tag satisfies: ['SRG-APP-000142', 'PP-MDM-431006']
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
