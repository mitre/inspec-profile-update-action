control 'SV-28978' do
  title 'Caching of logon credentials must be limited.'
  desc "The default Windows configuration caches the last logon credentials for users who log on interactively to a system.  This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable.  Even though the credential cache is well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain."
  desc 'fix', 'If the system is not a member of a domain, this is NA.
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)" to "2" logons or less.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-1090'
  tag rid: 'SV-28978r3_rule'
  tag gtitle: 'Caching of logon credentials'
  tag fix_id: 'F-63545r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
