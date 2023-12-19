control 'SV-208844' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'This prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.'
  desc 'check', 'To check if authentication is required for single-user mode, run the following command: 

$ grep SINGLE /etc/sysconfig/init

The output should be the following: 

SINGLE=/sbin/sulogin

If the output is different, this is a finding.'
  desc 'fix', 'Single-user mode is intended as a system recovery method, providing a single user root access to the system by providing a boot option at startup. By default, no authentication is performed if single-user mode is selected. 

To require entry of the root password even if the system is started in single-user mode, add or correct the following line in the file "/etc/sysconfig/init": 

SINGLE=/sbin/sulogin'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9097r357512_chk'
  tag severity: 'medium'
  tag gid: 'V-208844'
  tag rid: 'SV-208844r793629_rule'
  tag stig_id: 'OL6-00-000069'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-9097r357513_fix'
  tag 'documentable'
  tag legacy: ['SV-65153', 'V-50947']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
