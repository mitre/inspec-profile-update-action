control 'SV-38671' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful login attempts improves protection against password guessing attacks.'
  desc 'fix', 'Use the chsec command to configure the number of unsuccessful logins resulting in account lockout.  

# chsec -f /etc/security/user -s default -a loginretries=3 
# chsec -f /etc/security/user -s <user id> -a loginretries=3'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-766'
  tag rid: 'SV-38671r1_rule'
  tag stig_id: 'GEN000460'
  tag gtitle: 'GEN000460'
  tag fix_id: 'F-31633r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
