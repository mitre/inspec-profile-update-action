control 'SV-208930' do
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9183r357770_chk'
  tag severity: 'medium'
  tag gid: 'V-208930'
  tag rid: 'SV-208930r793716_rule'
  tag stig_id: 'OL6-00-000249'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9183r357771_fix'
  tag 'documentable'
  tag legacy: ['V-50815', 'SV-65021']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
