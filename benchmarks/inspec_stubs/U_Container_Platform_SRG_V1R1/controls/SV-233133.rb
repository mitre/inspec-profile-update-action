control 'SV-233133' do
  title 'The container platform must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'The container platform is responsible for offering services to users. These services could be across diverse user groups and data types. To protect information about the container platform, services, users, and data, it is important during error message generation to offer enough information to diagnose the error, but not reveal information that needs to be protected.'
  desc 'check', 'Review documentation and logs to determine if the container platform writes sensitive information such as passwords or private keys into the logs and administrative messages. 

If the container platform writes sensitive or potentially harmful information into the logs and administrative messages, this is a finding.'
  desc 'fix', 'Configure the container platform to not write sensitive information into the logs and administrative messages.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36069r599612_chk'
  tag severity: 'medium'
  tag gid: 'V-233133'
  tag rid: 'SV-233133r599613_rule'
  tag stig_id: 'SRG-APP-000266-CTR-000625'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-36037r599036_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
