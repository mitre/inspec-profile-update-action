control 'SV-87865' do
  title 'The firewall protecting the Samsung SDS EMM server platform must be configured so that all allowed ports, protocols, and services are approved for DoD use (on the DoD Ports, Protocols, Services Management (PPSM) Category Assurance Levels (CAL) list).'
  desc 'All ports, protocols, and services used on DoD networks must be approved and registered via the DoD Ports, Protocols, Services Management (PPSM) process. This is to insure that a risk assessment has been completed before a new port, protocol, or service is configured on a DoD network and has been approved by proper DoD authorities. Otherwise, the new port, protocol, or service could cause a vulnerability to the DoD network, which could be exploited by an adversary.

SFR ID: FMT_SMF.1.1(1) Refinement'
  desc 'check', 'Ask the MDM administrator for a list of ports, protocols and services that have been configured on the host-based firewall. Verify all allowed ports, protocols, and services are included on the DoD PPSM CAL list.

If any allowed ports, protocols, and services on the MDM host-based firewall are not included on the DoD PPSM CAL list, this is a finding.'
  desc 'fix', 'Turn off any ports, protocols, and services on the MDM host-based firewall that are not on the DoD Ports, Protocols, Services Management (PPSM) Category Assurance Levels (CAL) list.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73315r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73213'
  tag rid: 'SV-87865r1_rule'
  tag stig_id: 'SEMM-15-100060'
  tag gtitle: 'PP-MDM-991060'
  tag fix_id: 'F-79659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
