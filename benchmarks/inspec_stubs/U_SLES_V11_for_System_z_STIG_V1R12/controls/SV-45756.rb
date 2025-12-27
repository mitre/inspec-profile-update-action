control 'SV-45756' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', '# ps -ef |grep xinetd
If xinetd is not running, this check is not a finding.
# grep -v "^#" /etc/xinetd.conf
# grep disable /etc/xinetd.d/* |grep no
If no active services are found, and the inetd daemon is running, this is a finding.'
  desc 'fix', '# rcxinetd stop; insserv -r xinetd
     OR 

# service xinetd stop ; chkconfig xinetd off'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43109r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12005'
  tag rid: 'SV-45756r1_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'GEN003700'
  tag fix_id: 'F-39155r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
