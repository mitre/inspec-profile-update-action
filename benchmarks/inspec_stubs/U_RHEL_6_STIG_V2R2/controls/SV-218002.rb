control 'SV-218002' do
  title 'The SSH daemon must be configured with the Department of Defense (DoD) login banner.'
  desc 'The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.'
  desc 'check', %q(To determine how the SSH daemon's "Banner" option is set, run the following command: 

# grep -i Banner /etc/ssh/sshd_config

If a line indicating /etc/issue is returned, then the required value is set. 
If the required value is not set, this is a finding.)
  desc 'fix', 'To enable the warning banner and ensure it is consistent across the system, add or correct the following line in "/etc/ssh/sshd_config": 

Banner /etc/issue

Another section contains information on how to create an appropriate system-wide warning banner.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19483r377021_chk'
  tag severity: 'medium'
  tag gid: 'V-218002'
  tag rid: 'SV-218002r603264_rule'
  tag stig_id: 'RHEL-06-000240'
  tag gtitle: 'SRG-OS-000023'
  tag fix_id: 'F-19481r377022_fix'
  tag 'documentable'
  tag legacy: ['V-38615', 'SV-50416']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
