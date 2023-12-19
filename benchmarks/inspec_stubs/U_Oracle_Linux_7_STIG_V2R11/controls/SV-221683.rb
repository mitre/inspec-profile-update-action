control 'SV-221683' do
  title 'The Oracle Linux operating system must be configured so that passwords for new users are restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'If passwords are not being used for authentication, this is Not Applicable.

Verify the operating system enforces a 60-day maximum password lifetime restriction for new user accounts.

Check for the value of "PASS_MAX_DAYS" in "/etc/login.defs" with the following command:

# grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS 60

If the "PASS_MAX_DAYS" parameter value is not 60 or less, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a 60-day maximum password lifetime restriction.

Add the following line in "/etc/login.defs" (or modify the line to have the required value):

PASS_MAX_DAYS 60'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23398r419121_chk'
  tag severity: 'medium'
  tag gid: 'V-221683'
  tag rid: 'SV-221683r603260_rule'
  tag stig_id: 'OL07-00-010250'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-23387r419122_fix'
  tag 'documentable'
  tag legacy: ['SV-108209', 'V-99105']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
