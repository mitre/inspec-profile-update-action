control 'SV-215313' do
  title 'The AIX syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures.'
  desc "Unintentionally running a syslog server accepting remote messages puts the system at increased risk. Malicious syslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service."
  desc 'check', 'Verify "syslogd" is running with the "-R" option using command: 
# ps -ef | grep syslogd | grep -v grep 

The above command should yield the following output:
    root  4063356  3342368   0   Sep 11      -  0:01 /usr/sbin/syslogd -R

If the "-R" option is not present with the syslogd process, this is a finding.'
  desc 'fix', %q(Change the "syslogd" arguments in the src subsystem control and restart the "syslogd" daemon using the following commands:
# chssys -s syslogd -a '-R' 
# stopsrc -s syslogd 
# startsrc -s syslogd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16511r294390_chk'
  tag severity: 'medium'
  tag gid: 'V-215313'
  tag rid: 'SV-215313r508663_rule'
  tag stig_id: 'AIX7-00-002132'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16509r294391_fix'
  tag 'documentable'
  tag legacy: ['V-91677', 'SV-101775']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
