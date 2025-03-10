control 'SV-93685' do
  title 'IBM z/VM must be protected by an external firewall that has a deny-all, allow-by-exception policy.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Firewalls provide monitoring and control of communications at the external boundary of an information system to prevent and detect malicious and other unauthorized communications.'
  desc 'check', 'Ask the system administrator for a network system plan.

If there is no firewall defined for the IBM z/VM system, this is a finding.

If the firewall does not have a deny-all, allow-by-exception policy, this is a finding.'
  desc 'fix', 'Ensure that the network has a firewall installed that provides a deny-all, allow-by-exception protection for the IBM z/VM system.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78567r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78979'
  tag rid: 'SV-93685r1_rule'
  tag stig_id: 'IBMZ-VM-002360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85729r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
