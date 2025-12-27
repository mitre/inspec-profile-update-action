control 'SV-239600' do
  title 'The SLES for vRealize must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative timeserver (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', "A remote NTP server should be configured for time synchronization. To verify one is configured, open the following files:

# cat /etc/ntp.conf | grep server | grep -v '^#' 
# cat /etc/ntp.conf | grep peer | grep -v '^#' 
# cat /etc/ntp.conf | grep multicastclient | grep -v '^#' 

Confirm the servers and peers or multicastclient (as applicable) are local or an authoritative U.S. DoD source.

If a non-local/non-authoritative time-server is used, this is a finding."
  desc 'fix', 'To specify a remote NTP server for time synchronization, edit the file "/etc/ntp.conf". Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver by using the following command:

# echo "server [ntpserver]" >> /etc/ntp.conf

Replace [ntpserver] with one of the USNO time servers. This instructs the NTP software to contact that remote server to obtain time data.

Restart the service with: 

# service ntp restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42833r662249_chk'
  tag severity: 'medium'
  tag gid: 'V-239600'
  tag rid: 'SV-239600r662406_rule'
  tag stig_id: 'VROM-SL-001085'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-42792r662250_fix'
  tag 'documentable'
  tag legacy: ['SV-99321', 'V-88671']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
