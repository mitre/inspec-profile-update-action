control 'SV-77677' do
  title 'The SSH daemon must be configured with the Department of Defense (DoD) login banner.'
  desc 'The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.'
  desc 'check', 'To verify the Banner setting, run the following command: 

# grep -i "^Banner" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Banner /etc/issue", this is a finding.'
  desc 'fix', 'To set the Banner setting, add or correct the following line in "/etc/ssh/sshd_config":

Banner /etc/issue'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63187'
  tag rid: 'SV-77677r1_rule'
  tag stig_id: 'ESXI-06-000009'
  tag gtitle: 'SRG-OS-000023-VMM-000060'
  tag fix_id: 'F-69105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
