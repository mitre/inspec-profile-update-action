control 'SV-38670' do
  title 'The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.'
  desc 'Limiting simultaneous user logins can insulate the system from Denial of Service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.

If the defined value of 10 logins does not meet operational requirements, the site may define the permitted number of simultaneous login sessions based on operational requirements.

This limit is for the number of simultaneous login sessions for EACH user account. This is NOT a limit on the total number of simultaneous login sessions on the system.'
  desc 'check', '#grep maxulogs /etc/security/user | grep -v \\*

If no values are returned, or any value returned is not between 1 and 10, this is a finding.'
  desc 'fix', 'Configure the system to limit the number of simultaneous logins for user accounts with the chsec command. 

# chsec -f /etc/security/user -s default -a maxulogs=10
# chsec -f /etc/security/user –s [user] -a maxulogs=10'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36672r2_chk'
  tag severity: 'low'
  tag gid: 'V-22298'
  tag rid: 'SV-38670r2_rule'
  tag stig_id: 'GEN000450'
  tag gtitle: 'GEN000450'
  tag fix_id: 'F-31632r4_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
