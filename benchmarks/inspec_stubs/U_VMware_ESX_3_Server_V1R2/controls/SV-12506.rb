control 'SV-12506' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', 'First, determine if inetd/xinetd is running.
# ps -ef |grep inetd
If inetd is not running, this is not a finding.
# grep -v "^#" /etc/inetd.conf
If no active services are found, yet the inetd daemon is running, this is a finding.'
  desc 'fix', 'Remove or disable the inetd startup scripts and kill the service.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12005'
  tag rid: 'SV-12506r2_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'GEN003700'
  tag fix_id: 'F-11265r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
