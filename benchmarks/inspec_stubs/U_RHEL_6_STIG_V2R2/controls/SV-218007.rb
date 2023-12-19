control 'SV-218007' do
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
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19488r377036_chk'
  tag severity: 'medium'
  tag gid: 'V-218007'
  tag rid: 'SV-218007r603264_rule'
  tag stig_id: 'RHEL-06-000247'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-19486r377037_fix'
  tag 'documentable'
  tag legacy: ['SV-50421', 'V-38620']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
