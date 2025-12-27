control 'SV-219562' do
  title 'The system clock must be synchronized continuously, or at least daily.'
  desc 'Enabling the "ntpd" service ensures that the "ntpd" service will be running and that the system will synchronize its time to any servers specified. This is important whether the system is configured to be a client (and synchronize only its own clock) or it is also acting as an NTP server to other systems. Synchronizing time is essential for authentication services such as Kerberos, but it is also important for maintaining accurate logs and auditing possible security breaches.'
  desc 'check', 'Run the following command to determine the current status of the "ntpd" service: 

# service ntpd status

If the service is enabled, it should return the following: 

ntpd is running...

If the service is not running, this is a finding.'
  desc 'fix', 'The "ntpd" service can be enabled with the following command: 

# chkconfig ntpd on
# service ntpd start'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21287r462343_chk'
  tag severity: 'medium'
  tag gid: 'V-219562'
  tag rid: 'SV-219562r603263_rule'
  tag stig_id: 'OL6-00-000247'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-21286r462344_fix'
  tag 'documentable'
  tag legacy: ['V-50811', 'SV-65017']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
