control 'SV-218040' do
  title 'X Windows must not be enabled unless required.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', 'To verify the default runlevel is 3, run the following command: 

# grep initdefault /etc/inittab

The output should show the following: 

id:3:initdefault:


If it does not, this is a finding.'
  desc 'fix', %q(Setting the system's runlevel to 3 will prevent automatic startup of the X server. To do so, ensure the following line in "/etc/inittab" features a "3" as shown: 

id:3:initdefault:)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19521r377135_chk'
  tag severity: 'medium'
  tag gid: 'V-218040'
  tag rid: 'SV-218040r603264_rule'
  tag stig_id: 'RHEL-06-000290'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19519r377136_fix'
  tag 'documentable'
  tag legacy: ['V-38674', 'SV-50475']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
