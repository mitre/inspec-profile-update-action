control 'SV-27424' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'fix', '# service xinetd stop ; chkconfig xinetd off'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
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
