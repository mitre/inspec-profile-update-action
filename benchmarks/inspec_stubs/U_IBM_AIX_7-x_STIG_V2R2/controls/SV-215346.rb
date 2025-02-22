control 'SV-215346' do
  title 'The AIX rsh daemon must be disabled.'
  desc 'The rsh daemon permits username and passwords to be passed over the network in clear text.'
  desc 'check', 'From the command prompt, run the following command:
# grep -v "^#" /etc/inetd.conf |grep rshd 

The above command may show the daemon is enabled like this:
shell   stream  tcp6    nowait  root    /usr/sbin/rshd  rshd 

If the above grep command returned a line that contains "rshd", this is a finding.'
  desc 'fix', 'Edit the "/etc/inetd.conf" file and comment out the "rshd" service. 

Restart the inetd service:
# refresh -s inetd'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16544r294489_chk'
  tag severity: 'high'
  tag gid: 'V-215346'
  tag rid: 'SV-215346r508663_rule'
  tag stig_id: 'AIX7-00-003040'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16542r294490_fix'
  tag 'documentable'
  tag legacy: ['SV-101397', 'V-91299']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
