control 'SV-219558' do
  title 'The rlogind service must not be running.'
  desc 'The rlogin service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.'
  desc 'check', 'To check that the "rlogin" service is disabled in system boot configuration, run the following command:

# chkconfig "rlogin" --list

Output should indicate the "rlogin" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "rlogin" --list
rlogin off
OR
error reading information on service rlogin: No such file or directory

If the service is running, this is a finding.'
  desc 'fix', 'The "rlogin" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rlogin" service can be disabled with the following command: 

# chkconfig rlogin off'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21283r358214_chk'
  tag severity: 'high'
  tag gid: 'V-219558'
  tag rid: 'SV-219558r793815_rule'
  tag stig_id: 'OL6-00-000218'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-21282r358215_fix'
  tag 'documentable'
  tag legacy: ['SV-64767', 'V-50561']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
