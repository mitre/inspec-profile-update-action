control 'SV-38705' do
  title 'The system must not have the Calendar Manager Service Daemon (CMSD) service active.'
  desc 'The CMSD service for CDE is an unnecessary process that  runs a root and increases attack vector of the system.  Buffer overflow attacks against the CMSD process can potentially give access to the system.'
  desc 'check', "Check the /etc/inetd.conf file for active CMSD service.

# grep 'rpc\\.cmsd'  /etc/inetd.conf |grep -v \\#

If the CMSD service is enabled, this is a finding."
  desc 'fix', 'Edit /etc/inetd.conf and comment out the CMSD service. 

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29501'
  tag rid: 'SV-38705r1_rule'
  tag stig_id: 'GEN009160'
  tag gtitle: 'GEN009160'
  tag fix_id: 'F-33059r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
