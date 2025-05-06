control 'SV-213549' do
  title 'Production JBoss servers must be supported by the vendor.'
  desc 'The JBoss product is available as Open Source; however, the Red Hat vendor provides updates, patches and support for the JBoss product.  It is imperative that patches and updates be applied to JBoss in a timely manner as many attacks against JBoss focus on unpatched systems.  It is critical that support be obtained and made available.'
  desc 'check', 'Interview the system admin and have them either show documented proof of current support, or have them demonstrate their ability to access the Red Hat Enterprise Support portal.

Verify Red Hat  support includes coverage for the JBoss product.

If there is no current and active support from the vendor, this is a finding.'
  desc 'fix', 'Obtain vendor support from Red Hat.'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14772r296313_chk'
  tag severity: 'high'
  tag gid: 'V-213549'
  tag rid: 'SV-213549r615939_rule'
  tag stig_id: 'JBOS-AS-000680'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-14770r296314_fix'
  tag 'documentable'
  tag legacy: ['SV-76815', 'V-62325']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
