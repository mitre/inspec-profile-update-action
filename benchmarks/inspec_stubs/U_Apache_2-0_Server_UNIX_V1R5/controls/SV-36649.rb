control 'SV-36649' do
  title 'The httpd.conf MaxClients directive must be set properly.'
  desc 'These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.

From Apache.org: The MaxClients directive sets the limit on the number of simultaneous requests that will be served. Any connection attempts over the MaxClients limit will normally be queued, up to a number based on the ListenBacklog directive. Once a child process is freed at the end of a different request, the connection will then be serviced.

For non-threaded servers (i.e., prefork), MaxClients translates into the maximum number of child processes that will be launched to serve requests. The default value is 256; to increase it, you must also raise ServerLimit.

For threaded and hybrid servers (e.g. beos or worker) MaxClients restricts the total number of threads that will be available to serve clients. The default value for beos is 50. For hybrid MPMs the default value is 16 (ServerLimit) multiplied by the value of 25 (ThreadsPerChild). Therefore, to increase MaxClients to a value that requires more than 16 processes, you must also raise ServerLimit.'
  desc 'check', 'Open the httpd.conf file with an editor and search for the following directive:

MaxClients

The value needs to be 256 or less

If the directive is set improperly, this is a finding.

If the directive does not exist, this is NOT a finding because it will default to 256.  It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of increased value. If the site has this documentation, this should be marked as Not a Finding.'
  desc 'fix', 'Open the httpd.conf file with an editor and search for the following directive:

MaxClients

Set the directive to a value of 256 or less, add the directive if it does not exist.

It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-10982r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13730'
  tag rid: 'SV-36649r2_rule'
  tag stig_id: 'WA000-WWA032 A22'
  tag gtitle: 'WA000-WWA032'
  tag fix_id: 'F-13178r3_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
