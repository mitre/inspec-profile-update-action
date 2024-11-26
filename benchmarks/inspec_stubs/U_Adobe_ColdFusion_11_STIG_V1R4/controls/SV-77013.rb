control 'SV-77013' do
  title 'The ColdFusion missing template handler must be valid.'
  desc 'The structure and content of error messages need to be carefully considered by the organization and development team.  Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system.  

The missing template handler is used much like the 404 handler for a web server.  When the missing template handler is blank, a potential attacker may be sent information that reveals the ColdFusion version number.  Once the attacker has the version of ColdFusion being used, he can begin looking for specific attacks the version may be vulnerable to if not patched and secured properly.'
  desc 'check', %q(Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.  Validate that the "Missing Template Handler" setting is not blank and that the template specified is a valid.

If the "Missing Template Handler" parameter is blank, this is a finding.

If a template is specified, validate that the template exist.  The path and file given are relevant to the web servers' document root directory and not the OS root directory. For example, if the web servers' document root is /opt/webserver/wwwroot and the "Missing Template Handler" is set to /CFIDE/administrator/templates/missing_template_error.cfm, the full path to the template file is /opt/webserver/wwwroot/CFIDE/administrator/templates/missing_template_error.cfm

If the "Missing Template Handler" setting is not a valid file, this is a finding.)
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Specify a valid handler for missing templates and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62523'
  tag rid: 'SV-77013r1_rule'
  tag stig_id: 'CF11-06-000216'
  tag gtitle: 'SRG-APP-000266-AS-000168'
  tag fix_id: 'F-68443r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
