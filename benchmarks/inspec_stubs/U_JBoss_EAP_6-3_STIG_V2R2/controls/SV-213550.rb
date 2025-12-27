control 'SV-213550' do
  title 'The JRE installed on the JBoss server must be kept up to date.'
  desc 'The JBoss product is available as Open Source; however, the Red Hat vendor provides updates, patches and support for the JBoss product.  It is imperative that patches and updates be applied to JBoss in a timely manner as many attacks against JBoss focus on unpatched systems.  It is critical that support be obtained and made available.'
  desc 'check', 'Interview the system admin and obtain details on their patch management processes as it relates to the OS and the Application Server.

If there is no active, documented patch management process in use for these components, this is a finding.'
  desc 'fix', 'Configure the operating system and the application server to use a patch management system or process that ensures security-relevant updates are installed within the time period directed by the ISSM.'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14773r296316_chk'
  tag severity: 'high'
  tag gid: 'V-213550'
  tag rid: 'SV-213550r615939_rule'
  tag stig_id: 'JBOS-AS-000685'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-14771r296317_fix'
  tag 'documentable'
  tag legacy: ['SV-76817', 'V-62327']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
