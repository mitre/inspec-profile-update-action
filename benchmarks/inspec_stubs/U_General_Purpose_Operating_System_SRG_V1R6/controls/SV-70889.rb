control 'SV-70889' do
  title 'The operating system must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Verify the operating system limits the number of concurrent sessions to ten for all accounts and/or account types. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to limit the number of concurrent sessions to ten for all accounts and/or account types.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57199r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56629'
  tag rid: 'SV-70889r1_rule'
  tag stig_id: 'SRG-OS-000027-GPOS-00008'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-61525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
