control 'SV-33009' do
  title 'The HTTP request header fields must be limited.'
  desc 'Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directive limits the size of the various HTTP header sizes, thereby limiting the chances for a buffer overflow.

The LimitRequestFields directive allows the server administrator to modify the limit on the number of request header fields allowed in an HTTP request. A server needs this value to be larger than the number of fields that a normal client request might include. The number of request header fields used by a client rarely exceeds 20, but this may vary among different client implementations, often depending upon the extent to which a user has configured their browser to support detailed content negotiation. Optional HTTP extensions are often expressed using request header fields.

This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks. The value should be increased if normal clients see an error response from the server that indicates too many fields were sent in the request.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: LimitRequestFields

Every enabled LimitRequestFields value needs to be greater than 0. If any directive is set improperly, this is a finding.

Note: This can be set to a really high number (Current max is 32767), it just cannot be unspecified.'
  desc 'fix', 'Set LimitRequestFields Directive to a value greater than 0.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33690r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13737'
  tag rid: 'SV-33009r1_rule'
  tag stig_id: 'WA000-WWA062 W22'
  tag gtitle: 'WA000-WWA062'
  tag fix_id: 'F-29309r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
