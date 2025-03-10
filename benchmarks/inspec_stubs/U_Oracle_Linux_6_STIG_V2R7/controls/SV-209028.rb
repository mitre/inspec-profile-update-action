control 'SV-209028' do
  title 'Emergency accounts must be provisioned with an expiration date.'
  desc 'When emergency accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.'
  desc 'check', 'For every emergency account, run the following command to obtain its account aging and expiration information: 

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented.
 
If any emergency accounts have no expiration date set or do not expire within a documented time frame, this is a finding.'
  desc 'fix', 'In the event emergency accounts are required, configure the system to terminate them after a documented time period.

For every emergency account, run the following command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" appropriately: 

# chage -E [YYYY-MM-DD] [USER]

"[YYYY-MM-DD]" indicates the documented expiration date for the account.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9281r357869_chk'
  tag severity: 'low'
  tag gid: 'V-209028'
  tag rid: 'SV-209028r793749_rule'
  tag stig_id: 'OL6-00-000298'
  tag gtitle: 'SRG-OS-000123'
  tag fix_id: 'F-9281r357870_fix'
  tag 'documentable'
  tag legacy: ['SV-65199', 'V-50993']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
