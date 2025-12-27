control 'SV-79175' do
  title 'The OHS server root directory must not be on a network share.'
  desc 'Sharing of the web server directory where the executables are stored is a security risk when a web server is involved.  Users that have access to the share may not be administrative users.  These users could make changes to the web server without going through proper change control or the users could inadvertently delete executables that are key to the proper operation of the web server.  Any unnecessary exposure increases the risk that someone could exploit that access and either compromises the web server or cause web server performance problems.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf.

2. Search for the "ServerRoot" directive at the OHS server configuration scope.

3. If the directive value is used as a network share (e.g., ps -ef | grep nfs, ps -ef | grep smb, etc.), this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf.

2. Search for the "ServerRoot" directive at the OHS server configuration scope.

3. Remove the share that is associated with the directory specified as a value for the "ServerRoot" directive.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65427r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64685'
  tag rid: 'SV-79175r1_rule'
  tag stig_id: 'OH12-1X-000224'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70615r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
