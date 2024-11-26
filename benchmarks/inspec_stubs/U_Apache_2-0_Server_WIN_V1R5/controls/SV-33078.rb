control 'SV-33078' do
  title 'Web server system files must conform to minimum file permission requirements.'
  desc 'This check verifies that the key web server system configuration files are owned by the SA or Web Manager controlled account. These same files which control the configuration of the web server, and thus its behavior, must also be accessible by the account which runs the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform.'
  desc 'check', 'Locate and examine the httpd.conf file. Look for the section: <ServerRoot>. This section will contain the path to the configuration and binary files.

Permissions on this directory files should be:

Administrators: Full control
System: Full Control
WebAdmin: Full Control
WebUser: Read, Execute
Apache Service Account: Read, Execute

Permissions for the /config directory should be as follows:
(This is a sub directory to the main apache directory identified above)
Administrators: Full control
System: Read
WebAdmin: Modify
Apache Service Account: Read

Permissions for the /bin directory should be as follows:
(This is a sub directory to the main apache directory identified above)
Administrators: Full control
System: Read, Execute
WebAdmin: Modify
Apache Service Account: Read, Execute

Permissions for the /logs directory should be as follows:
(This is a sub directory to the main apache directory identified above)
Administrators: Read
System: Full Control
WebAdmin: Read
Apache Service Account: Modify
Auditors: Full Control

Permissions for the /htdocs directory (DocumentRoot) should be as follows:
(This is a sub directory to the main apache directory identified above)
Administrators: Full control
System: Read
WebAdmin: Modify
Apache Service Account: Read

If any of the above permissions are less restrictive, this is a finding.

NOTE: There may be additional directories based the local implementation, and permissions should apply to directories of similar content. Ex. all web content directories should follow the permissions for /htdocs.'
  desc 'fix', 'Set file permissions on the web server systems files to meet minimum file permissions requirements.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33750r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2259'
  tag rid: 'SV-33078r1_rule'
  tag stig_id: 'WG300 W22'
  tag gtitle: 'WG300'
  tag fix_id: 'F-29386r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2, ECLP-1'
end
