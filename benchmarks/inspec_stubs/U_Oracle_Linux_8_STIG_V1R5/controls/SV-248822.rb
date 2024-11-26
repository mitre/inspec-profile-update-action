control 'SV-248822' do
  title 'OL 8 must disable network management of the chrony daemon.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate. 
 
Minimizing the exposure of the server functionality of the chrony daemon diminishes the attack surface. 
 
Note that USNO offers authenticated NTP service to DoD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.'
  desc 'check', %q(Verify OL 8 disables network management of the chrony daemon with the following command: 
 
$ sudo grep -w 'cmdport' /etc/chrony.conf 
 
cmdport 0 
 
If the "cmdport" option is not set to "0" or is commented out or missing, this is a finding.)
  desc 'fix', 'Configure OL 8 to disable network management of the chrony daemon by adding/modifying the following line in the "/etc/chrony.conf" file. 
 
cmdport 0'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52256r780030_chk'
  tag severity: 'low'
  tag gid: 'V-248822'
  tag rid: 'SV-248822r780032_rule'
  tag stig_id: 'OL08-00-030742'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-52210r780031_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
