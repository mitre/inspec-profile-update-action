control 'SV-218046' do
  title 'Emergency accounts must be provisioned with an expiration date.'
  desc 'When emergency accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.'
  desc 'check', 'For every emergency account, run the following command to obtain its account aging and expiration information: 

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented. 
If any emergency accounts have no expiration date set or do not expire within a documented time frame, this is a finding.'
  desc 'fix', 'In the event emergency accounts are required, configure the system to terminate them after a documented time period. For every emergency account, run the following command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" appropriately: 

# chage -E [YYYY-MM-DD] [USER]

"[YYYY-MM-DD]" indicates the documented expiration date for the account.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19527r377153_chk'
  tag severity: 'low'
  tag gid: 'V-218046'
  tag rid: 'SV-218046r603264_rule'
  tag stig_id: 'RHEL-06-000298'
  tag gtitle: 'SRG-OS-000123'
  tag fix_id: 'F-19525r377154_fix'
  tag 'documentable'
  tag legacy: ['V-38690', 'SV-50491']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
