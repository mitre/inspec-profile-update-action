control 'SV-80781' do
  title 'The HP FlexFabric Switch must employ automated mechanisms to assist in the tracking of security incidents.'
  desc "Despite the investment in perimeter defense technologies, enclaves are still faced with detecting, analyzing, and remediating network breaches and exploits that have made it past the HP FlexFabric Switch. An automated incident response infrastructure allows network operations to immediately react to incidents by identifying, analyzing, and mitigating any network device compromise. Incident response teams can perform root cause analysis, determine how the exploit proliferated, and identify all affected nodes, as well as contain and eliminate the threat.

The HP FlexFabric Switch assists in the tracking of security incidents by logging detected security events. The audit log and network device application logs capture different types of events. The audit log tracks audit events occurring on the components of the HP FlexFabric Switch. The application log tracks the results of the HP FlexFabric Switch content filtering function. These logs must be aggregated into a centralized server and can be used as part of the organization's security incident tracking and analysis."
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch: 

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66291'
  tag rid: 'SV-80781r1_rule'
  tag stig_id: 'HFFS-ND-000138'
  tag gtitle: 'SRG-APP-000516-NDM-000342'
  tag fix_id: 'F-72367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000833']
  tag nist: ['CM-6 b', 'IR-5 (1)']
end
