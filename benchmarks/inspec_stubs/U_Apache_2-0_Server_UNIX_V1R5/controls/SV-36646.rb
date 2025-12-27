control 'SV-36646' do
  title 'The httpd.conf MinSpareServers directive must be set properly.'
  desc 'These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.

From Apache.org: The MinSpareServers directive sets the desired minimum number of idle child server processes. An idle process is one which is not handling a request. If there are fewer than MinSpareServers idle, then the parent process creates new children at a maximum rate of 1 per second.

Tuning of this parameter should only be necessary on very busy sites. Setting this parameter to a large number is almost always a bad idea.'
  desc 'check', 'Open the httpd.conf file with an editor and search for the following directive:

MinSpareServers

The value needs to be between 5 and 10

If the directive is set improperly, this is a finding.

If the directive is not found, you will need to review the httpd.conf file to see if there are other .conf files that are included of "linked" to the httpd.conf. The other conf files may contain these directives.

If the directive does not exist, this is NOT a finding because it will default to 5.  It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of increased  or decreased value. If the site has this documentation, this should be marked as Not a Finding.'
  desc 'fix', 'Open the httpd.conf file with an editor and search for the following directive:

MinSpareServers

Set the directive to a value of between 5 and 10, add the directive if it does not exist.

It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-10980r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13728'
  tag rid: 'SV-36646r2_rule'
  tag stig_id: 'WA000-WWA028 A22'
  tag gtitle: 'WA000-WWA028'
  tag fix_id: 'F-13176r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
