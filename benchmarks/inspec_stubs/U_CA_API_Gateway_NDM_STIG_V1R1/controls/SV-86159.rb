control 'SV-86159' do
  title 'The CA API Gateway must automatically remove or disable emergency accounts, except the emergency administration account, after 72 hours.'
  desc 'Emergency accounts are administrator accounts which are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. 

If emergency accounts remain active when no longer needed, they may be used to gain unauthorized access. The risk is greater for the network device since these accounts have elevated privileges. To mitigate this risk, automated termination of these accounts must be set upon account creation.

It is important to note the difference between emergency accounts and the emergency administration account. The emergency administration account, also known as the account of last resort, is an infrequently used account used by network administrators only when network or normal logon/access is not available. The emergency administration account is not subject to automatic termination dates.'
  desc 'check', 'Verify expiry of account with command: 

chage -l "USERNAME"

and look at the "Account expires" line for expiry date.

If the expiry date is more than "72" hours after emergency account creation, this is a finding.'
  desc 'fix', 'For existing accounts, set expiry time of an account using command: 

chage -E "YYYY-MM-DD" "USERNAME

For new accounts, create using command: 

useradd -e <expiry_date> USERNAME

where the expiry date in YYYY-MM-DD format is when you wish the account to expire.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71535'
  tag rid: 'SV-86159r1_rule'
  tag stig_id: 'CAGW-DM-000180'
  tag gtitle: 'SRG-APP-000234-NDM-000272'
  tag fix_id: 'F-77855r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
