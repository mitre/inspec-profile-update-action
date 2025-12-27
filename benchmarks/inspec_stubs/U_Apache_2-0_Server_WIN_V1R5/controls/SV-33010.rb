control 'SV-33010' do
  title 'The HTTP request header field size must be limited.'
  desc 'Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directive limits the size of the various HTTP header sizes, thereby limiting the chances for a buffer overflow. 

The LimitRequestFieldSize directive allows the server administrator to reduce or increase the limit on the allowed size of an HTTP request header field. A server needs this value to be large enough to hold any one header field from a normal client request. The size of a normal request header field will vary greatly among different client implementations, often depending upon the extent to which a user has configured their browser to support detailed content negotiation. SPNEGO authentication headers can be up to 12392 bytes.

This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: LimitRequestFieldSize

If no LimitRequestFieldSize directives exist, this is a Finding. Although the default value is 8190, this directive must be explicitly set.

For every LimitRequestFieldSize directive found, the value needs to be 8190. If any directive is set improperly, this is a finding.

NOTE: This value may vary in size based on the application that is being supported by the web server. This vulnerability can be documented locally by the ISSM/ISSO if the site has operational reasons for an increased or decreased value. If the ISSM/ISSO has approved this change in writing, this should be marked as Not a Finding.'
  desc 'fix', 'Ensure the LimitRequestFieldSize is explicitly configured and set to 8190 or ISSO/ISSM-approved value.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33692r5_chk'
  tag severity: 'medium'
  tag gid: 'V-13738'
  tag rid: 'SV-33010r3_rule'
  tag stig_id: 'WA000-WWA064 W22'
  tag gtitle: 'WA000-WWA064'
  tag fix_id: 'F-29310r4_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
