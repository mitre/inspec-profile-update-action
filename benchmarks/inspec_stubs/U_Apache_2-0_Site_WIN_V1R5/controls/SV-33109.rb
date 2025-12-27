control 'SV-33109' do
  title 'Web content directories must not be anonymously shared.'
  desc 'Sharing of web server content is a security risk when a web server is involved. Users accessing the share anonymously could experience privileged access to the content of such directories. Network sharable directories expose those directories and their contents to unnecessary access. Any unnecessary exposure increases the risk that someone could exploit that access and either compromises the web content or cause web server performance problems.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives: DocumentRoot & ServerRoot

Note the location following each enabled DocumentRoot and ServerRoot directives.

Navigate to the DocumentRoot, and ServerRoot, using the path identified above. Right click on the directory to be examined. Select Properties > Select the “Sharing” tab. If either folder is shared, this is a finding. 

NOTE: The presence of operating system shares on the web server is not an issue as long as the shares are not part of the web content directories. The use of shares to move content from one environment to another is permitted if the following conditions are met: they are approved by the ISSM/ISSO, the shares are restricted to only allow administrators write access, the use of the shares does not bypass the sites approval process for posting new content to the web server, and developers are only permitted read access to these directories.'
  desc 'fix', 'Remove the shares from the applicable directories.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33770r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2226'
  tag rid: 'SV-33109r2_rule'
  tag stig_id: 'WG210 W22'
  tag gtitle: 'WG210'
  tag fix_id: 'F-29407r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
