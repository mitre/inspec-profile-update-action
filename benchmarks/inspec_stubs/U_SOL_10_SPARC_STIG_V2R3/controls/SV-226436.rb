control 'SV-226436' do
  title 'The system must use at least two time sources for clock synchronization.'
  desc "A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  For redundancy, two time sources are required so synchronization continues to function if one source fails.  

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary.  If the system is completely isolated, this requirement is not applicable.

NOTE:  For the Network Time Protocol (NTP), the requirement is two servers, but it is recommended to configure at least four distinct time servers which allow NTP to effectively exclude a time source not consistent with the others.  The system's local clock must be excluded from the count of time sources."
  desc 'check', %q(Determine the zone that you are currently securing.

# zonename

If the command output is not "global", this is not applicable.

Check the NTP daemon configuration for at least two external servers.
# grep '^server' /etc/inet/ntp.conf | egrep -v '(127.127.1.1|127.127.1.0)'
If less than two servers or external reference clocks (127.127.x.x other than 127.127.1.0 or 127.127.1.1) are listed, this is a finding.)
  desc 'fix', 'Add an additional server line to /etc/inet/ntp.conf for each additional NTP server.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28597r482672_chk'
  tag severity: 'medium'
  tag gid: 'V-226436'
  tag rid: 'SV-226436r854400_rule'
  tag stig_id: 'GEN000242'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-28585r482673_fix'
  tag 'documentable'
  tag legacy: ['SV-26303', 'V-22291']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
