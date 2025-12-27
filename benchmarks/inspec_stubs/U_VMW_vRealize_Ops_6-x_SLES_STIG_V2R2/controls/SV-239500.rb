control 'SV-239500' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If SLES for vRealize does not limit the lifetime of passwords and force users to change their passwords, there is the risk that SLES for vRealize passwords could be compromised.'
  desc 'check', %q(Check the max days field of "/etc/shadow" by running the following command:

# cat /etc/shadow | cut -d':' -f1,5 | egrep -v "([0|60])" | grep -v ":$"

If any results are returned, this is a finding.)
  desc 'fix', 'Set the maximum time period between password changes for each [USER] account to "60" days. The command in the check text will give you a list of users that need to be updated to be in compliance.

# passwd -x 60 [USER]

The DoD requirement is "60" days.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42733r661949_chk'
  tag severity: 'medium'
  tag gid: 'V-239500'
  tag rid: 'SV-239500r661951_rule'
  tag stig_id: 'VROM-SL-000390'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-42692r661950_fix'
  tag 'documentable'
  tag legacy: ['SV-99121', 'V-88471']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
