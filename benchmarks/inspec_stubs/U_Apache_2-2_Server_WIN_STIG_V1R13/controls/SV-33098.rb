control 'SV-33098' do
  title 'Web server and/or operating system information must be protected.'
  desc 'The web server response header of an HTTP response can contain several fields of information including the requested HTML page. The information included in this response can be web server type and version, operating system and version, and ports associated with the web server. This provides the malicious user valuable information without the use of extensive tools.'
  desc 'check', 'Locate the httpd.conf file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directive: ServerTokens

The directive ServerTokens must be set to “Prod” (ex. ServerTokens Prod). This directive controls whether Server response header field that is sent back to clients that includes a description of the OS-type of the server as well as information about compiled-in modules.

If the web server or operating system information is sent to the client via the server response header, this is a finding. If the directive does not exist, this would be a finding as it defaults to Full.'
  desc 'fix', 'Ensure the web server is configured to not advertise the web server and operating system information to the client.'
  impact 0.3
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33763r1_chk'
  tag severity: 'low'
  tag gid: 'V-6724'
  tag rid: 'SV-33098r1_rule'
  tag stig_id: 'WG520 W22'
  tag gtitle: 'WG520'
  tag fix_id: 'F-29400r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
