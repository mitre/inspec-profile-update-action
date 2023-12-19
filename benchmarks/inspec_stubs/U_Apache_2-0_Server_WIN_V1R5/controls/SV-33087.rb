control 'SV-33087' do
  title 'All web server documentation, sample code, example applications, and tutorials must be removed from a production web server.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server. A production web server may only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). Delete all directories that contain samples and any scripts used to execute the samples. If there is a requirement to maintain these directories at the site on non-production servers for training purposes, have NTFS permissions set to only allow access to authorized users (i.e., web administrators and systems administrators). Sample applications or scripts have not been evaluated and approved for use and may introduce vulnerabilities to the system.'
  desc 'check', 'Query the SA to determine if all directories that contain samples and any scripts used to execute the samples have been removed from the server.

Each web server has its own list of sample files. This may change with the software versions, but the following are some examples of what to look for (This is not a definitive list of sample files, but only an example of the common samples that are provided with the associated web server. This list will be updated as additional information is discovered.):

[Drive Letter]:/[directory path]/apache2/manual/*.*
[Drive Letter]:/[directory path]/apache2/conf/extra/*.*
[Drive Letter]:/[directory path]/apache2/cgi-bin/printenv
[Drive Letter]:/[directory path]/apache2/cgi-bin/test-cgi

If there is a requirement to maintain these directories at the site for training or other such purposes, have permissions or set the permissions to only allow access to authorized users.

If any sample files are found on the web server, this is a finding.'
  desc 'fix', 'Ensure sample code and documentation have been removed from the web server.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33756r1_chk'
  tag severity: 'high'
  tag gid: 'V-13621'
  tag rid: 'SV-33087r1_rule'
  tag stig_id: 'WG385 W22'
  tag gtitle: 'WG385'
  tag fix_id: 'F-29392r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Any sample application or sample executable script found on the production web server will be a CAT I finding. 

Any web server documentation or sample file found on the production web server and accessible to web users or non-administrators will be a CAT III finding.

Any web server documentation or sample file found on the production web server and accessible only to SAs or to web administrators is permissible and not a finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
