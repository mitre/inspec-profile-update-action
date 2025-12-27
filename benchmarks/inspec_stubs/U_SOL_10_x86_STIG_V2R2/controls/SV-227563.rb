control 'SV-227563' do
  title 'The system must use time sources local to the enclave.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  The network architecture should provide multiple time servers within an enclave that provide local service to the enclave and synchronize with time sources outside of the enclave.

If this server is an enclave time server, this requirement is not applicable.

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary.  If the system is completely isolated, this requirement is not applicable.'
  desc 'check', %q(Determine the zone that you are currently securing.

# zonename

If the command output is not "global", this is not applicable.

Check the NTP daemon configuration. 
# grep '^server' /etc/inet/ntp.conf
If an NTP server is listed outside of the enclave, this is a finding.)
  desc 'fix', 'Remove the server line from /etc/inet/ntp.conf for each NTP server that is external to the enclave.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29725r488225_chk'
  tag severity: 'low'
  tag gid: 'V-227563'
  tag rid: 'SV-227563r603266_rule'
  tag stig_id: 'GEN000244'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-29713r488226_fix'
  tag 'documentable'
  tag legacy: ['V-22292', 'SV-26305']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
