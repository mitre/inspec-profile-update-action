control 'SV-222987' do
  title '$CATALINA_BASE/conf/ folder must be owned by root,  group tomcat.'
  desc 'Tomcat file permissions must be restricted. The standard configuration is to have Tomcat files contained in the conf/ folder as members of the "tomcat" group. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the Tomcat user rather than root. This means that even if an attacker compromises the Tomcat process, they cannot change the Tomcat configuration, deploy new web applications, or modify existing web applications. The Tomcat process runs with a umask of 0027 to maintain these permissions. Note that running Tomcat in a Docker environment can impact how file permissions and user ownership settings are applied. Due to associated Docker configuration complexities, the STIG is scoped for standalone rather than virtual Docker deployments.

If the ISSM determines the operational need to allow application admins access to change the Tomcat configuration outweighs the risk of limiting that access, then they can change the group membership to accommodate.  Ownership must not be changed.  The ISSM should take the exposure of the system to high risk networks into account.'
  desc 'check', 'Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_BASE/conf -follow -maxdepth 0 \\(  ! -user root -o ! -group tomcat \\) -ls

If ISSM risk acceptance specifies deviation from requirement based on operational/application needs, this is not a finding if the group permissions are set in accordance with the risk acceptance. Ownership must not be changed.

If no folders are displayed, this is not a finding.

If results indicate the $CATALINA_BASE/conf folder ownership and group membership is not set to root:tomcat, this is a finding.'
  desc 'fix', 'If operational/application requirements specify different group file permissions, obtain ISSM risk acceptance and set permissions according to risk acceptance.  Ownership must not be changed. 

Run the following commands on the Tomcat server:

sudo find $CATALINA_BASE/conf -maxdepth 0 \\( ! -user root \\) | sudo xargs chown root

sudo find $CATALINA_BASE/conf -maxdepth 0 \\( ! -group tomcat \\) | sudo xargs chgrp tomcat'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24659r426405_chk'
  tag severity: 'medium'
  tag gid: 'V-222987'
  tag rid: 'SV-222987r754842_rule'
  tag stig_id: 'TCAT-AS-001220'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-24648r426406_fix'
  tag 'documentable'
  tag legacy: ['SV-111497', 'V-102557']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
