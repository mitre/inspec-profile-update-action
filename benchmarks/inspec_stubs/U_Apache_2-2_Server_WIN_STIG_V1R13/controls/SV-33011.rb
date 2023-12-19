control 'SV-33011' do
  title 'The HTTP request line must be limited.'
  desc "Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directive limits the size of the various HTTP header sizes, thereby limiting the chances for a buffer overflow. 

The LimitRequestLine directive allows the server administrator to reduce or increase the limit on the allowed size of a client's HTTP request-line. Since the request-line consists of the HTTP method, URI, and protocol version, the LimitRequestLine directive places a restriction on the length of a request-URI allowed for a request on the server. A server needs this value to be large enough to hold any of its resource names, including any information that might be passed in the query part of a GET request.

This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks."
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: LimitRequestLine

Every enabled LimitRequestLine value needs to be 8190. If any directive is set improperly, this is a Finding.
If no LimitRequestLine directives exist, this is a Finding. Although the default value is 8190, this directive must be explicitly set.

NOTE: This value may vary in size based on the application that is being supported by the web server. This vulnerability can be documented locally by the ISSM/ISSO if the site has operational reasons for an increased or decreased value. If the ISSM/ISSO has approved this change in writing, this should be marked as Not a Finding.'
  desc 'fix', 'Set LimitRequestLine to 8190 or approved value. If no LimitRequestLine directives exist, explicitly add the directive and set to 8190.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33693r3_chk'
  tag severity: 'medium'
  tag gid: 'V-13739'
  tag rid: 'SV-33011r3_rule'
  tag stig_id: 'WA000-WWA066 W22'
  tag gtitle: 'WA000-WWA066'
  tag fix_id: 'F-29311r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
