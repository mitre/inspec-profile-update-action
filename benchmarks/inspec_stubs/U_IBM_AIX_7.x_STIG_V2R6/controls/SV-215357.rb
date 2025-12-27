control 'SV-215357' do
  title 'If IPv6 is not utilized on AIX server, the autoconf6 daemon must be disabled.'
  desc '"autoconf6" is used to automatically configure IPv6 interfaces at boot time. Running this service may allow other hosts on the same physical subnet to connect via IPv6, even when the network does not support it. Disable this unless you use IPv6 on the server.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/autoconf6" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "autoconf6" entry by running command: 
# chrctcp -d autoconf6'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16555r569497_chk'
  tag severity: 'medium'
  tag gid: 'V-215357'
  tag rid: 'SV-215357r513945_rule'
  tag stig_id: 'AIX7-00-003051'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16553r569498_fix'
  tag 'documentable'
  tag legacy: ['SV-101439', 'V-91341']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
