control 'SV-69097' do
  title 'The DNS server implementation must be configured to allow DNS administrators to change the auditing to be performed on all DNS server components, based on all selectable event criteria.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near real-time, within minutes, or within hours.

For a DNS server, the actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server is configured to allow DNS administrators to change the auditing to be performed on all DNS server components, based on all selectable event criteria.

If the DNS server is not configured to allow DNS administrators to change the auditing to be performed on all DNS server components, based on all selectable event criteria, this is a finding.'
  desc 'fix', 'Configure the DNS server to allow DNS administrators to change the auditing to be performed on all DNS server components, based on all selectable event criteria.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55473r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54851'
  tag rid: 'SV-69097r1_rule'
  tag stig_id: 'SRG-APP-000353-DNS-000045'
  tag gtitle: 'SRG-APP-000353-DNS-000045'
  tag fix_id: 'F-59709r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
