control 'SV-27424' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', '# ps -ef |grep xinetd
If xinetd is not running, this check is not a finding.
# grep -v "^#" /etc/xinetd.conf
# grep disable /etc/xinetd.d/* |grep no
If no active services are found, and the inetd daemon is running, this is a finding.'
  desc 'fix', '# service xinetd stop ; chkconfig xinetd off'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-28610r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12005'
  tag rid: 'SV-27424r1_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'GEN003700'
  tag fix_id: 'F-24696r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
