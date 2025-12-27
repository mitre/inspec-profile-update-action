control 'SV-69091' do
  title 'The DNS server implementation must be configured to generate audit records for failed security verification tests so that the ISSO and ISSM can be notified of the failures.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain. Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

The DNS server should be configured to generate audit records whenever a self-test fails. The OS/NDM is responsible for generating notification messages related to this audit record.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server is configured to generate audit records for failed security verification tests so that the ISSO and ISSM can be notified of the failures. If the DNS server is not configured to generate such audit records, this is a finding.'
  desc 'fix', 'Configure the DNS server to generate audit records for failed security verification tests so that the ISSO and ISSM can be notified of the failures.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55467r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54845'
  tag rid: 'SV-69091r1_rule'
  tag stig_id: 'SRG-APP-000275-DNS-000040'
  tag gtitle: 'SRG-APP-000275-DNS-000040'
  tag fix_id: 'F-59703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
