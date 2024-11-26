control 'SV-219569' do
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21294r358247_chk'
  tag severity: 'medium'
  tag gid: 'V-219569'
  tag rid: 'SV-219569r793826_rule'
  tag stig_id: 'OL6-00-000290'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-21293r358248_fix'
  tag 'documentable'
  tag legacy: ['V-50885', 'SV-65091']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
