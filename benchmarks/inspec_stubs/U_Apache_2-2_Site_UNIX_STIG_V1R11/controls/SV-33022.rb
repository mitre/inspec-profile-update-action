control 'SV-33022' do
  title 'Web content directories must not be anonymously shared.'
  desc 'Sharing web content is a security risk when a web server is involved. Users accessing the share anonymously could experience privileged access to the content of such directories. Network sharable directories expose those directories and their contents to unnecessary access. Any unnecessary exposure increases the risk that someone could exploit that access and either compromises the web content or cause web server performance problems.'
  desc 'check', 'To view the DocumentRoot enter the following command: 

grep "DocumentRoot" /usr/local/apache2/conf/httpd.conf 

To view the ServerRoot enter the following command: 

grep "serverRoot" /usr/local/apache2/conf/httpd.conf 

Note the location following the DocumentRoot and ServerRoot directives. 

Enter the following commands to determine if file sharing is running: 

ps -ef | grep nfs, ps -ef | grep smb 

If results are returned, determine the shares and confirm they are not in the same directory as listed above, If they are, this is a finding.'
  desc 'fix', 'Remove the shares from the applicable directories.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33704r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2226'
  tag rid: 'SV-33022r1_rule'
  tag stig_id: 'WG210 A22'
  tag gtitle: 'WG210'
  tag fix_id: 'F-2275r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
