control 'SV-215392' do
  title 'The Internet Network News (INN) server must be disabled on AIX.'
  desc 'Internet Network News (INN) servers access Usenet newsfeeds and store newsgroup articles. INN servers use the Network News Transfer Protocol (NNTP) to transfer information from the Usenet to the server and from the server to authorized remote hosts. 

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', 'From the command prompt, run the following command:
# ps -ef | egrep "innd|nntpd" 

If the above command produced any result, this is a finding. 

Check if "innd" or "nntpd" is started from "/etc/onetd.conf" using the following command:
# egrep "innd|nntpd" /etc/inetd.conf | grep -v ^#

If the above command produced any result, this is a finding. 

Check if "innd" or "nntpd" is added as a subsystem to the System Resource Controller (SRC):
# lssrc -s innd
# lssrc -s nntpd

If the above commands found that "innd" or "nntpd" is defined in SRC, this is a finding.'
  desc 'fix', %q(To stop "innd" or "nntpd" from running, use the following commands:
# stopsrc -s innd
# stopsrc -s nntpd

Some versions of "innd" and "nntpd" need the following commands to stop them: 
# kill -1 [innd_pid]
# kill -1 [nntpd_pid]

To remove "innd" and 'nntpd" from SRC, run the following commands:
# rmssys -s innd
# rmssys -s nntpd

To stop running "innd" and "nntpd" from "/etc/inetd.conf", comment out the "innd" and "nntpd" lines in "/etc/inetd.conf", then refresh the "inetd":
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16590r294627_chk'
  tag severity: 'medium'
  tag gid: 'V-215392'
  tag rid: 'SV-215392r508663_rule'
  tag stig_id: 'AIX7-00-003087'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16588r294628_fix'
  tag 'documentable'
  tag legacy: ['SV-101513', 'V-91415']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
