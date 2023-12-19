control 'SV-102637' do
  title 'The Apache web server document directory must be in a separate partition from the Apache web servers system files.'
  desc 'A web server is used to deliver content on the request of a client. The content delivered to a client must be controlled, allowing only hosted application files to be accessed and delivered. To allow a client access to system files of any type is a major security risk that is entirely avoidable. Obtaining such access is the goal of directory traversal and URL manipulation vulnerabilities. To facilitate such access by misconfiguring the web document (home) directory is a serious error. In addition, having the path on the same drive as the system folder compounds potential attacks, such as drive space exhaustion.'
  desc 'check', 'Determine whether the public web server has a two-way trusted relationship with any private asset located within the network. Private web server resources (e.g., drives, folders, printers, etc.) will not be directly mapped to or shared with public web servers.

If sharing is selected for any web folder, this is a finding.

If private resources (e.g., drives, partitions, folders/directories, printers, etc.) are shared with the public web server, this is a finding.'
  desc 'fix', 'Configure the public web server to not have a trusted relationship with any system resource that is also not accessible to the public. Web content is not to be shared via Microsoft shares or NFS mounts.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92549'
  tag rid: 'SV-102637r1_rule'
  tag stig_id: 'AS24-W2-000580'
  tag gtitle: 'SRG-APP-000233-WSR-000146'
  tag fix_id: 'F-98791r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
