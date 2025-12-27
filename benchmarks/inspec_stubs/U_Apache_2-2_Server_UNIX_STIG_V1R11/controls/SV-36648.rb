control 'SV-36648' do
  title 'The httpd.conf MaxSpareServers directive must be set properly.'
  desc 'These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.

From Apache.org:The MaxSpareServers directive sets the desired maximum number of idle child server processes. An idle process is one which is not handling a request. If there are more than MaxSpareServers idle, then the parent process will kill off the excess processes.

Tuning of this parameter should only be necessary on very busy sites. Setting this parameter to a large number is almost always a bad idea. If you are trying to set the value equal to or lower than MinSpareServers, Apache will automatically adjust it to MinSpareServers + 1.'
  desc 'check', 'Open the httpd.conf file with an editor and search for the following directive:

MaxSpareServers

The value needs to be 10 or less

If the directive is set improperly, this is a finding.

If the directive is not found, you will need to review the httpd.conf file to see if there are other .conf files that are included of "linked" to the httpd.conf. The other conf files may contain these directives.


If the directive does not exist, this is NOT a finding because it will default to 10.  It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of increased value. If the site has this documentation, this should be marked as Not a Finding.'
  desc 'fix', 'Open the httpd.conf file with an editor and search for the following directive:

MaxSpareServers

Set the directive to a value of 10 or less, add the directive if it does not exist.

It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.'
  impact 0.3
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-10981r2_chk'
  tag severity: 'low'
  tag gid: 'V-13729'
  tag rid: 'SV-36648r2_rule'
  tag stig_id: 'WA000-WWA030 A22'
  tag gtitle: 'WA000-WWA030'
  tag fix_id: 'F-13177r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
