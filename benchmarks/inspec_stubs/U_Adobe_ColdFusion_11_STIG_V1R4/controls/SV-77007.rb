control 'SV-77007' do
  title 'ColdFusion must protect Session Cookies from being read by scripts.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly during preparation for transmission.  By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie.  Setting cookie properties (i.e., HTTPOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.'
  desc 'check', 'Within the Administrator Console, navigate to the "Memory Variables" page under the "Server Settings" menu.

If "HTTPOnly" is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Memory Variables" page under the "Server Settings" menu.  Check "HTTPOnly" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63321r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62517'
  tag rid: 'SV-77007r1_rule'
  tag stig_id: 'CF11-05-000199'
  tag gtitle: 'SRG-APP-000441-AS-000258'
  tag fix_id: 'F-68437r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
