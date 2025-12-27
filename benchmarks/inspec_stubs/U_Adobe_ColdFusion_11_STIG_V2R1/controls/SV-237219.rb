control 'SV-237219' do
  title 'ColdFusion must encrypt cookies.'
  desc 'Preventing the disclosure of transmitted information requires that the application server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission.  This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of session cookies is especially important since an attacker can grab the session id and hijack the already authenticated session.  There are several methods to protect cookie data, and one of those methods is to encrypt the cookie.  This can only be done if all the hosted sites are SSL/TLS enabled.'
  desc 'check', 'Within the Administrator Console, navigate to the "Memory Variables" page under the "Server Settings" menu.

If "Secure Cookie" is not checked, this is a finding.'
  desc 'fix', 'Navigate to the "Memory Variables" page under the "Server Settings" menu.  Check "Secure Cookie" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40438r641750_chk'
  tag severity: 'medium'
  tag gid: 'V-237219'
  tag rid: 'SV-237219r641752_rule'
  tag stig_id: 'CF11-05-000196'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag fix_id: 'F-40401r641751_fix'
  tag 'documentable'
  tag legacy: ['SV-77001', 'V-62511']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
