control 'SV-209023' do
  title 'The xorg-x11-server-common (X Windows) package must not be installed, unless required.'
  desc 'Unnecessary packages should not be installed to decrease the attack surface of the system.'
  desc 'check', 'To ensure the X Windows package group is removed, run the following command: 

$ rpm -qi xorg-x11-server-common

The output should be: 

package xorg-x11-server-common is not installed

If it is not, this is a finding.'
  desc 'fix', 'Removing all packages which constitute the X Window System ensures users or malicious software cannot start X. To do so, run the following command: 

# yum groupremove "X Window System"'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9276r357854_chk'
  tag severity: 'low'
  tag gid: 'V-209023'
  tag rid: 'SV-209023r603263_rule'
  tag stig_id: 'OL6-00-000291'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9276r357855_fix'
  tag 'documentable'
  tag legacy: ['V-50887', 'SV-65093']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
