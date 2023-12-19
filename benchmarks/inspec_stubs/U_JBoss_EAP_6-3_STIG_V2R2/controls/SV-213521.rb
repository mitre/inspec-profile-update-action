control 'SV-213521' do
  title 'JBoss QuickStarts must be removed.'
  desc 'JBoss QuickStarts are demo applications that can be deployed quickly.  Demo applications are not written with security in mind and often open new attack vectors.  QuickStarts must be removed.'
  desc 'check', 'Examine the <JBOSS_HOME> folder.  If a jboss-eap-6.3.0-GA-quickstarts folder exits, this is a finding.'
  desc 'fix', 'Delete the QuickStarts folder.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14744r296229_chk'
  tag severity: 'medium'
  tag gid: 'V-213521'
  tag rid: 'SV-213521r615939_rule'
  tag stig_id: 'JBOS-AS-000235'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-14742r296230_fix'
  tag 'documentable'
  tag legacy: ['SV-76757', 'V-62267']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
