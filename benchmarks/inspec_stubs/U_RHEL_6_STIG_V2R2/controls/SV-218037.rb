control 'SV-218037' do
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
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19518r377126_chk'
  tag severity: 'low'
  tag gid: 'V-218037'
  tag rid: 'SV-218037r603264_rule'
  tag stig_id: 'RHEL-06-000287'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19516r377127_fix'
  tag 'documentable'
  tag legacy: ['SV-50470', 'V-38669']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
