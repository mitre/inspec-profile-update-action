control 'SV-229013' do
  title 'The BIG-IP appliance must be configured to employ automated mechanisms to assist in the tracking of security incidents.'
  desc "Despite the investment in perimeter defense technologies, enclaves are still faced with detecting, analyzing, and remediating network breaches and exploits that have made it past the network device. An automated incident response infrastructure allows network operations to immediately react to incidents by identifying, analyzing, and mitigating any network device compromise. Incident response teams can perform root cause analysis, determine how the exploit proliferated, and identify all affected nodes, as well as contain and eliminate the threat.

The network device assists in the tracking of security incidents by logging detected security events. The audit log and network device application logs capture different types of events. The audit log tracks audit events occurring on the components of the network device. The application log tracks the results of the network device content filtering function. These logs must be aggregated into a centralized server and can be used as part of the organization's security incident tracking and analysis."
  desc 'check', 'Verify the BIG-IP appliance is configured to employ automated mechanisms to assist in the tracking of security incidents.

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Log Destinations.

Verify a log destination is configured for a system that employs automated mechanisms to assist in the tracking of security incidents.

If such automated mechanisms are not employed, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to direct logs to a system that employs automated mechanisms to assist in the tracking of security incidents.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31328r518083_chk'
  tag severity: 'medium'
  tag gid: 'V-229013'
  tag rid: 'SV-229013r557520_rule'
  tag stig_id: 'F5BI-DM-000281'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31305r518084_fix'
  tag 'documentable'
  tag legacy: ['V-60237', 'SV-74667']
  tag cci: ['CCI-000366', 'CCI-000833']
  tag nist: ['CM-6 b', 'IR-5 (1)']
end
