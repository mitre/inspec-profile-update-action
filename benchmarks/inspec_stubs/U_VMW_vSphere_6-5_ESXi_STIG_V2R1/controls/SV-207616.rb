control 'SV-207616' do
  title 'The ESXi host SSH daemon must not allow authentication using an empty password.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitEmptyPasswords no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

PermitEmptyPasswords no'
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7871r364247_chk'
  tag severity: 'high'
  tag gid: 'V-207616'
  tag rid: 'SV-207616r388482_rule'
  tag stig_id: 'ESXI-65-000015'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7871r364248_fix'
  tag 'documentable'
  tag legacy: ['V-93977', 'SV-104063']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
