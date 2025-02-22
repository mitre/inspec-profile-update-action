control 'SV-33236' do
  title 'HTTP request methods must be limited.'
  desc 'The HTTP 1.1 protocol supports several request methods which are rarely used and potentially high risk. For example, methods such as PUT and DELETE are rarely used and should be disabled in keeping with the primary security principal of minimize features and options. Also since the usage of these methods is typically to modify resources on the web server, they should be explicitly disallowed. For normal web server operation, you will typically need to allow only the GET, HEAD and POST request methods. This will allow for downloading of web pages and submitting information to web forms. The OPTIONS request method will also be allowed as it is used to request which HTTP request methods are allowed.'
  desc 'check', 'Note: If HTTP commands (GET, PUT, POST, DELETE) are not being used and server is solely configured as a proxy server, this is Not Applicable.

Enter the following command:

more /usr/local/apache2/conf/httpd.conf

For every enabled <Directory> directive (except root), ensure the following entry exists:

Order allow,deny

<LimitExcept GET POST OPTIONS>
Deny from all
</LimitExcept>

If the statement above is found in the root directory statement (i.e. <Directory />), this is a finding. 

If the statement above is found enabled but without the appropriate LimitExcept or Order statement, this is a finding. 

If the statement is not found inside an enabled <Directory> directive, this is a finding.

Note: If the LimitExcept statement above is operationally limiting. This should be explicitly documented with the Web Manager, at which point this can be considered not a finding.'
  desc 'fix', 'Edit the httpd.conf file and add the following entries for every enabled directory except root.

Order allow,deny

<LimitExcept GET POST OPTIONS>
     Deny from all
</LimitExcept>'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33833r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26396'
  tag rid: 'SV-33236r2_rule'
  tag stig_id: 'WA00565 A22'
  tag gtitle: 'WA00565'
  tag fix_id: 'F-29499r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
