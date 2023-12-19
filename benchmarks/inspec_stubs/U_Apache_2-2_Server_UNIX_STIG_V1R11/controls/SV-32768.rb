control 'SV-32768' do
  title 'The HTTP request line must be limited.'
  desc "Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directives limits the size of the various HTTP header sizes thereby limiting the chances for a buffer overflow. 

The LimitRequestLine directive allows the server administrator to reduce or increase the limit on the allowed size of a client's HTTP request-line. Since the request-line consists of the HTTP method, URI, and protocol version, the LimitRequestLine directive places a restriction on the length of a request-URI allowed for a request on the server. A server needs this value to be large enough to hold any of its resource names, including any information that might be passed in the query part of a GET request.

This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks."
  desc 'check', 'To view the LimitRequestLine value enter the following command:

grep "LimitRequestLine" /usr/local/apache2/conf/httpd.conf.

If the value of LimitRequestLine is not set to 8190, this is a finding.
If no LimitRequestLine directives exist, this is a Finding. Although the default value is 8190, this directive must be explicitly set.'
  desc 'fix', 'Edit the httpd.conf file and set the LimitRequestLine to 8190 or other approved value. If no LimitRequestLine directives exist, explicitly add the directive and set to 8190.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33624r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13739'
  tag rid: 'SV-32768r2_rule'
  tag stig_id: 'WA000-WWA066 A22'
  tag gtitle: 'WA000-WWA066'
  tag fix_id: 'F-29258r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
