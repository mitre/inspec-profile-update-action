control 'SV-222619' do
  title 'The ISSO must ensure an account management process is implemented, verifying only authorized users can gain access to the application, and individual accounts designated as inactive, suspended, or terminated are promptly removed.'
  desc 'A comprehensive account management process will ensure that only authorized users can gain access to applications and that individual accounts designated as inactive, suspended, or terminated are promptly deactivated. Such a process greatly reduces the risk that accounts will be misused, hijacked, or data compromised.'
  desc 'check', 'Interview the application representative to verify that a documented process exists for user and system account creation, termination, and expiration.

Obtain a list of recently departed personnel and verify that their accounts were removed or deactivated on all systems in a timely manner (e.g., less than two days).
 
If a documented account management process does not exist or unauthorized users have active accounts, this is a finding.'
  desc 'fix', 'Establish an account management process.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24289r493765_chk'
  tag severity: 'medium'
  tag gid: 'V-222619'
  tag rid: 'SV-222619r508029_rule'
  tag stig_id: 'APSC-DV-002880'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24278r493766_fix'
  tag 'documentable'
  tag legacy: ['V-70291', 'SV-84913']
  tag cci: ['CCI-002121', 'CCI-000366']
  tag nist: ['AC-2 f', 'CM-6 b']
end
