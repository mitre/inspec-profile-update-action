control 'SV-237216' do
  title 'ColdFusion must have a custom request queue time-out page.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

Limiting the knowledge given to an attacker about the effects of his attack and possible solutions to further his attack is important.  This is especially important when the attacker is trying to find the limits needed to exhaust resources and cause a DoS.  To limit feedback to the attacker on his efforts, a custom time-out page should be used.  The message returned should only inform the user that they should wait and retry their request again.  The message must not disclose that the queue timed out.'
  desc 'check', %q(Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.  Validate that the "Request Queue Timeout Page" setting is set to a valid and custom page.

If "Request Queue Timeout Page" is blank or is set to /CFIDE/administrator/templates/request_timeout_error.cfm, this is a finding.

If a page is specified, validate that the file exist.  The path and file given are relevant to the web servers' document root directory and not the OS root directory. For example, if the web servers' document root is /opt/webserver/wwwroot and the "Request Queue Timeout Page" is set to /CFIDE/administrator/templates/timeout_error.cfm, the full path to the template file is /opt/webserver/wwwroot/CFIDE/administrator/templates/timeout_error.cfm

If the "Request Queue Timeout Page" setting is not set to a valid page, this is a finding.)
  desc 'fix', 'Navigate to the "Request Tuning" page under the "Server Settings" menu.  Set "Request Queue Timeout Page" to a custom and valid error page and select the "Submit Changes" button.'
  impact 0.3
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40435r641741_chk'
  tag severity: 'low'
  tag gid: 'V-237216'
  tag rid: 'SV-237216r641743_rule'
  tag stig_id: 'CF11-05-000193'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40398r641742_fix'
  tag 'documentable'
  tag legacy: ['SV-76995', 'V-62505']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
