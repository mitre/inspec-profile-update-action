control 'SV-239266' do
  title 'The ESXi host SSH daemon must be configured with the DoD logon banner.'
  desc 'The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^Banner" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Banner /etc/issue", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

Banner /etc/issue'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42499r674725_chk'
  tag severity: 'medium'
  tag gid: 'V-239266'
  tag rid: 'SV-239266r674727_rule'
  tag stig_id: 'ESXI-67-000009'
  tag gtitle: 'SRG-OS-000023-VMM-000060'
  tag fix_id: 'F-42458r674726_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
