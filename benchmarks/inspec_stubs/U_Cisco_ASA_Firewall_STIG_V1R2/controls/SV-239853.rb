control 'SV-239853' do
  title 'The Cisco ASA must immediately use updates made to policy enforcement mechanisms such as firewall rules, security policies, and security zones.'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the Ports, Protocols, Services Management (PPSM) Category Assurance Levels (CAL) list, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.'
  desc 'check', 'By default, when you change a rule-based policy such as access rules, the changes become effective immediately. With transactional model configured, the rules are not active until after compilation.

Review the ASA configuration and verify that the following command is not configured.

asp rule-engine transactional-commit access-group

If transactional-commit access-group has been configured, this is a finding.'
  desc 'fix', 'Remove the command asp rule-engine transactional-commit access-group

ASA(config)# no asp rule-engine transactional-commit access-group'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43086r665843_chk'
  tag severity: 'medium'
  tag gid: 'V-239853'
  tag rid: 'SV-239853r665845_rule'
  tag stig_id: 'CASA-FW-000020'
  tag gtitle: 'SRG-NET-000019-FW-000004'
  tag fix_id: 'F-43045r665844_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
