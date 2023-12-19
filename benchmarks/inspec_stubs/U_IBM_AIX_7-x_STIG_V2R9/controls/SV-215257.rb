control 'SV-215257' do
  title 'The AIX rexec daemon must not be running.'
  desc 'The exec service is used to execute a command sent from a remote server. The username and passwords are passed over the network in clear text and therefore insecurely. Unless required the rexecd daemon will be disabled. This function, if required, should be facilitated through SSH.'
  desc 'check', 'Determine if the "rexec" daemon is running by running the following command:
# grep "^exec[[:blank:]]" /etc/inetd.conf

If the above grep command returned a line that contains "rexecd", this is a finding.'
  desc 'fix', %q(Disable the "rexecd" entry in "/etc/inetd.conf" using command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'exec' -p 'tcp6'

Reload the inetd process:
# refresh -s inetd)
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16455r294222_chk'
  tag severity: 'high'
  tag gid: 'V-215257'
  tag rid: 'SV-215257r877396_rule'
  tag stig_id: 'AIX7-00-002058'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16453r294223_fix'
  tag 'documentable'
  tag legacy: ['V-91303', 'SV-101401']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
