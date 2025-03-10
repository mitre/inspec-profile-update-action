control 'SV-70261' do
  title 'Cookies exchanged between the web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e. HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine how to disable client-side scripts from reading cookies.

If the web server is not configured to disallow client-side scripts from reading cookies, this is a finding.'
  desc 'fix', 'Configure the web server to disallow client-side scripts the capability of reading cookie information.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56577r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56007'
  tag rid: 'SV-70261r2_rule'
  tag stig_id: 'SRG-APP-000439-WSR-000154'
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag fix_id: 'F-60885r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
