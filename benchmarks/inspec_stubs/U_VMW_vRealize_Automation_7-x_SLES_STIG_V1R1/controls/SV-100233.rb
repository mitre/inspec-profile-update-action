control 'SV-100233' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', %q(Check the max days field of /etc/shadow by running the following command:

# cat /etc/shadow | cut -d':' -f1,5 | egrep -v "([0|60])" | grep -v ":$"

If any results are returned, this is a finding.)
  desc 'fix', 'Set the maximum time period between password changes for each [USER] account to "60" days. The command in the check text will give you a list of users that need to be updated to be in compliance.

# passwd -x 60 [USER]

The DoD requirement is "60" days.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89583'
  tag rid: 'SV-100233r1_rule'
  tag stig_id: 'VRAU-SL-000395'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-96325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
