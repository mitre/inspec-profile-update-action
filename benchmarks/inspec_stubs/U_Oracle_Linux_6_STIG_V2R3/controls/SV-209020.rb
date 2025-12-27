control 'SV-209020' do
  title 'The postfix service must be enabled for mail delivery.'
  desc 'Local mail delivery is essential to some system maintenance and notification tasks.'
  desc 'check', 'Run the following command to determine the current status of the "postfix" service:

# service postfix status

If the service is enabled, it should return the following:

postfix is running...

If the service is not enabled, this is a finding.'
  desc 'fix', 'The Postfix mail transfer agent is used for local mail delivery within the system. The default configuration only listens for connections to the default SMTP port (port 25) on the loopback interface (127.0.0.1). It is recommended to leave this service enabled for local mail delivery. The "postfix" service can be enabled with the following command: 

# chkconfig postfix on
# service postfix start'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9273r357845_chk'
  tag severity: 'low'
  tag gid: 'V-209020'
  tag rid: 'SV-209020r603263_rule'
  tag stig_id: 'OL6-00-000287'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9273r357846_fix'
  tag 'documentable'
  tag legacy: ['SV-65085', 'V-50879']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
