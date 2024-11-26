control 'SV-208915' do
  title 'The rshd service must not be running.'
  desc 'The rsh service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.'
  desc 'check', 'To check that the "rsh" service is disabled in system boot configuration, run the following command:

# chkconfig "rsh" --list

Output should indicate the "rsh" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "rsh" --list
rsh off
OR
error reading information on service rsh: No such file or directory

If the service is running, this is a finding.'
  desc 'fix', 'The "rsh" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rsh" service can be disabled with the following command: 

# chkconfig rsh off'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9168r357725_chk'
  tag severity: 'high'
  tag gid: 'V-208915'
  tag rid: 'SV-208915r603263_rule'
  tag stig_id: 'OL6-00-000214'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-9168r357726_fix'
  tag 'documentable'
  tag legacy: ['V-50557', 'SV-64763']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
