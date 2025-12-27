control 'SV-218008' do
  title 'The system clock must be synchronized to an authoritative DoD time source.'
  desc 'Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended.'
  desc 'check', 'A remote NTP server should be configured for time synchronization. To verify one is configured, open the following file. 

/etc/ntp.conf

In the file, there should be a section similar to the following: 

# --- OUR TIMESERVERS -----
server [ntpserver]


If this is not the case, this is a finding.'
  desc 'fix', 'To specify a remote NTP server for time synchronization, edit the file "/etc/ntp.conf". Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver. 

server [ntpserver]

This instructs the NTP software to contact that remote server to obtain time data.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19489r377039_chk'
  tag severity: 'medium'
  tag gid: 'V-218008'
  tag rid: 'SV-218008r603264_rule'
  tag stig_id: 'RHEL-06-000248'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-19487r377040_fix'
  tag 'documentable'
  tag legacy: ['V-38621', 'SV-50422']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
