control 'SV-234892' do
  title 'The SUSE operating system must employ user passwords with a maximum lifetime of 60 days.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the SUSE operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the SUSE operating system passwords could be compromised.'
  desc 'check', %q(Verify that the SUSE operating system enforces a maximum user password age of 60 days or less.

Check that the SUSE operating system enforces 60 days or less as the maximum user password age with the following command:

> sudo awk -F: '$5 > 60 || $5 == "" {print $1 ":" $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to enforce a maximum password age of each [USER] account to 60 days. The command in the check text will give a list of users that need to be updated to be in compliance:

> sudo passwd -x 60 [USER]

The DoD requirement is 60 days.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38080r618945_chk'
  tag severity: 'medium'
  tag gid: 'V-234892'
  tag rid: 'SV-234892r622137_rule'
  tag stig_id: 'SLES-15-020230'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-38043r618946_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
