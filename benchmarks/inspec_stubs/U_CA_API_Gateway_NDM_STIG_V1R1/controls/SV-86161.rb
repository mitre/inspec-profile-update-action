control 'SV-86161' do
  title 'The CA API Gateway must activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.'
  desc "Predictable failure prevention requires organizational planning to address device failure issues. If components key to maintaining the device's security fail to function, the device could continue operating in an insecure state. If appropriate actions are not taken when a network device failure occurs, a denial of service condition may occur which could result in mission failure since the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the network device must activate a system alert message, send an alarm, or shut down."
  desc 'check', %q(Verify "/usr/local/bin/failtest" script exists and is executable. 

Verify crontab runs "/usr/local/bin/failtest" every minute by checking cron's logfile "/var/log/cron".

If "/usr/local/bin/failtest" does not exist or it is not executable, this is a finding.)
  desc 'fix', 'Install and configure (setup SNMP trap dest/authentication) alerter script in /usr/local/bin/failtest. Configure cron to run "/usr/local/bin/failtest" every minute as indicated by /etc/crontab entry'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71537'
  tag rid: 'SV-86161r1_rule'
  tag stig_id: 'CAGW-DM-000190'
  tag gtitle: 'SRG-APP-000268-NDM-000274'
  tag fix_id: 'F-77857r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end
