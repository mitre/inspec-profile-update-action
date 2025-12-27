control 'SV-237226' do
  title 'The ColdFusion site-wide error handler must be valid.'
  desc 'The structure and content of error messages need to be carefully considered by the organization and development team.  Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system.  

When the site-wide error handler is blank, information can be presented to an attacker that may expose the cause of exceptions.  Having this information, the attacker can then begin attacking this error trying to get the server to fail and cause a DoS, expose PII, or gain access to server resources.  A custom site-wide error handler should be created and used that discloses the same generic message to the user for all exceptions and the error must be logged so that the error can be investigated.'
  desc 'check', %q(Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.  Validate that the "Site-wide Error Handler" setting is not blank and that the template specified is valid.  

If the "Site-wide Error Handler" parameter is blank, this is a finding.

If a template is specified, validate that the template exist.  The path and file given are relevant to the web servers' document root directory and not the OS root directory. For example, if the web server's document root is /opt/webserver/wwwroot and the "Site-wide Error Handler" is set to /CFIDE/administrator/templates/secure_profile_error.cfm, the full path to the template file is /opt/webserver/wwwroot/CFIDE/administrator/templates/secure_profile_error.cfm

If the "Site-wide Error Handler" setting is not a valid file, this is a finding.)
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Specify a custom and valid site-wide error handler and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40445r641771_chk'
  tag severity: 'medium'
  tag gid: 'V-237226'
  tag rid: 'SV-237226r641773_rule'
  tag stig_id: 'CF11-06-000217'
  tag gtitle: 'SRG-APP-000266-AS-000168'
  tag fix_id: 'F-40408r641772_fix'
  tag 'documentable'
  tag legacy: ['SV-77015', 'V-62525']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
