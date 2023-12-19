control 'SV-226465' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password.'
  desc 'check', %q(Check the max days field (the 5th field) of /etc/shadow.
# awk -F: '{print $1 ":" $5;}' /etc/shadow
If the max days field is equal to 0 or greater than 60 for any account that is not password-locked, this is a finding.)
  desc 'fix', 'Set the max days field to 60 for all user accounts.
# passwd -x 60 <user> 
Set the MAXWEEKS parameter in /etc/default/passwd to a positive, non-zero value of 8 or less.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28626r482771_chk'
  tag severity: 'medium'
  tag gid: 'V-226465'
  tag rid: 'SV-226465r603265_rule'
  tag stig_id: 'GEN000700'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-28614r482772_fix'
  tag 'documentable'
  tag legacy: ['V-11976', 'SV-39845']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
