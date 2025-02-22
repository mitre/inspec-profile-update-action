control 'SV-207612' do
  title 'The ESXi host SSH daemon must be configured to use only the SSHv2 protocol.'
  desc 'SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used. Only SSH protocol version 2 connections should be permitted.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^Protocol" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Protocol 2", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

Add or correct the following line in "/etc/ssh/sshd_config":

Protocol 2'
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7867r364235_chk'
  tag severity: 'high'
  tag gid: 'V-207612'
  tag rid: 'SV-207612r378610_rule'
  tag stig_id: 'ESXI-65-000011'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag fix_id: 'F-7867r364236_fix'
  tag 'documentable'
  tag legacy: ['V-93969', 'SV-104055']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
