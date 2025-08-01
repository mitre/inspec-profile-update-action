control 'SV-218237' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password.'
  desc 'check', 'Check the max days field (the 5th field) of /etc/shadow.
# more /etc/shadow
If the max days field is equal to 0 or greater than 60 for any user, this is a finding.'
  desc 'fix', 'Set the max days field to 60 for all user accounts.
# passwd -x 60 <user>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19712r554048_chk'
  tag severity: 'medium'
  tag gid: 'V-218237'
  tag rid: 'SV-218237r603259_rule'
  tag stig_id: 'GEN000700'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-19710r554049_fix'
  tag 'documentable'
  tag legacy: ['V-11976', 'SV-64083']
  tag cci: ['CCI-000180', 'CCI-000199']
  tag nist: ['IA-5 f', 'IA-5 (1) (d)']
end
