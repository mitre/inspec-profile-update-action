control 'SV-218498' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', '# ps -ef |grep xinetd
If xinetd is not running, this check is not a finding.
# grep -v "^#" /etc/xinetd.conf
# grep disable /etc/xinetd.d/* |grep no
If no active services are found, and the inetd daemon is running, this is a finding.'
  desc 'fix', '# service xinetd stop ; chkconfig xinetd off'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19973r562627_chk'
  tag severity: 'medium'
  tag gid: 'V-218498'
  tag rid: 'SV-218498r603259_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19971r562628_fix'
  tag 'documentable'
  tag legacy: ['V-12005', 'SV-64231']
  tag cci: ['CCI-000305', 'CCI-000381']
  tag nist: ['CM-7 (2)', 'CM-7 a']
end
