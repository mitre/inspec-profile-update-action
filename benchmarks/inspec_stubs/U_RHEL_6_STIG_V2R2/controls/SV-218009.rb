control 'SV-218009' do
  title 'Mail relaying must be restricted.'
  desc 'This ensures "postfix" accepts mail messages (such as cron job reports) from the local system only, and not from the network, which protects it from network attack.'
  desc 'check', 'If the system is an authorized mail relay host, this is not applicable. 

Run the following command to ensure postfix accepts mail messages from only the local system: 

$ grep inet_interfaces /etc/postfix/main.cf

If properly configured, the output should show only "localhost". 
If it does not, this is a finding.'
  desc 'fix', 'Edit the file "/etc/postfix/main.cf" to ensure that only the following "inet_interfaces" line appears: 

inet_interfaces = localhost'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19490r377042_chk'
  tag severity: 'medium'
  tag gid: 'V-218009'
  tag rid: 'SV-218009r603264_rule'
  tag stig_id: 'RHEL-06-000249'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19488r377043_fix'
  tag 'documentable'
  tag legacy: ['SV-50423', 'V-38622']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
