control 'SV-68895' do
  title 'The ALG must generate error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Providing too much information in error messages risks compromising the data and security of the application and system.

Organizations carefully consider the structure/content of error messages. The required information within error messages will vary based on the protocol and error condition. Information that could be exploited by adversaries includes, for example, ICMP messages that reveal the use of firewalls or access-control lists.'
  desc 'check', 'Verify the ALG generates error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries.

If the ALG does not generate error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries, this is a finding.'
  desc 'fix', 'Configure the ALG to generate error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55269r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54649'
  tag rid: 'SV-68895r1_rule'
  tag stig_id: 'SRG-NET-000273-ALG-000129'
  tag gtitle: 'SRG-NET-000273-ALG-000129'
  tag fix_id: 'F-59505r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
