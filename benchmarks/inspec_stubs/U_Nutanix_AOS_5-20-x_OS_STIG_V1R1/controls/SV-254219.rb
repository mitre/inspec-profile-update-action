control 'SV-254219' do
  title 'Nutanix AOS must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', %q(Confirm Nutanix AOS is configured to enforce a 60-day maximum password lifetime.

$ sudo grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS 60

If the "PASS_MAX_DAYS" parameter value is not "60" or less, or is commented out, this is a finding.

$ sudo awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure the password maximum age by running the following command:

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57704r846743_chk'
  tag severity: 'medium'
  tag gid: 'V-254219'
  tag rid: 'SV-254219r846745_rule'
  tag stig_id: 'NUTX-OS-001350'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-57655r846744_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
