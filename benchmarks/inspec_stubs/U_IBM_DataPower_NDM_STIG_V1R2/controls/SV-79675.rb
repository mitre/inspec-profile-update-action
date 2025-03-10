control 'SV-79675' do
  title 'The DataPower Gateway must employ automated mechanisms to assist in the tracking of security incidents.'
  desc "Despite the investment in perimeter defense technologies, enclaves are still faced with detecting, analyzing, and remediating network breaches and exploits that have made it past the network device. An automated incident response infrastructure allows network operations to immediately react to incidents by identifying, analyzing, and mitigating any network device compromise. Incident response teams can perform root cause analysis, determine how the exploit proliferated, and identify all affected nodes, as well as contain and eliminate the threat.

The network device assists in the tracking of security incidents by logging detected security events. The audit log and network device application logs capture different types of events. The audit log tracks audit events occurring on the components of the network device. The application log tracks the results of the network device content filtering function. These logs must be aggregated into a centralized server and can be used as part of the organization's security incident tracking and analysis."
  desc 'check', 'Go to Administration >> Miscellaneous >> Manage Log Targets. Verify the log target. If no log target exists, this is a finding.'
  desc 'fix', 'Go to Administration >> Miscellaneous >> Manage Log Targets. Click the log target or add one. Go to the Event Subscriptions tab and click on the event categories that are required to be audited.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65185'
  tag rid: 'SV-79675r1_rule'
  tag stig_id: 'WSDP-NM-000140'
  tag gtitle: 'SRG-APP-000516-NDM-000342'
  tag fix_id: 'F-71125r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000833']
  tag nist: ['CM-6 b', 'IR-5 (1)']
end
