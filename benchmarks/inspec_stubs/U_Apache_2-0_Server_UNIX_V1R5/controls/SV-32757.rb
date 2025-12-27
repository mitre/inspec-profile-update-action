control 'SV-32757' do
  title 'The HTTP request header fields must be limited.'
  desc 'Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directives limits the size of the various HTTP header sizes thereby limiting the chances for a buffer overflow.

The LimitRequestFields directive allows the server administrator to modify the limit on the number of request header fields allowed in an HTTP request. A server needs this value to be larger than the number of fields that a normal client request might include. The number of request header fields used by a client rarely exceeds 20, but this may vary among different client implementations, often depending upon the extent to which a user has configured their browser to support detailed content negotiation. Optional HTTP extensions are often expressed using request header fields.

This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks. The value should be increased if normal clients see an error response from the server that indicates too many fields were sent in the request.'
  desc 'check', 'To view the LimitRequestFields value enter the following command:

grep "LimitRequestFields" /usr/local/apache2/conf/httpd.conf.

If the value of LimitRequestFields is not set to a value greater than 0, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and set LimitRequestFields Directive to a value greater than 0.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33620r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13737'
  tag rid: 'SV-32757r1_rule'
  tag stig_id: 'WA000-WWA062 A22'
  tag gtitle: 'WA000-WWA062'
  tag fix_id: 'F-29252r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
