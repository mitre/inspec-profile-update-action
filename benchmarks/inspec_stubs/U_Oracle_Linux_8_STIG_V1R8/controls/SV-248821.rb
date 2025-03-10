control 'SV-248821' do
  title 'OL 8 must disable the chrony daemon from acting as a server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate. 
 
Minimizing the exposure of the server functionality of the chrony daemon diminishes the attack surface. 
 
Note that USNO offers authenticated NTP service to DOD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/DOD-customers for more information.'
  desc 'check', %q(Note: If the system is approved and documented by the information system security officer (ISSO) to function as an NTP time server, this requirement is Not Applicable.

Verify OL 8 disables the chrony daemon from acting as a server with the following command: 
 
     $ sudo grep -w 'port' /etc/chrony.conf 
     port 0 
 
If the "port" option is not set to "0" or is commented out or missing, this is a finding.)
  desc 'fix', 'Configure OL 8 to disable the chrony daemon from acting as a server by adding or modifying the following line in the "/etc/chrony.conf" file. 
 
     port 0'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52255r928554_chk'
  tag severity: 'low'
  tag gid: 'V-248821'
  tag rid: 'SV-248821r928556_rule'
  tag stig_id: 'OL08-00-030741'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-52209r928555_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
