control 'SV-227811' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', 'Determine if inetd is running,
# svcs -a | grep inetd
If inetd is not running, this check is not a finding.
# inetadm | grep -v disabled
If no enabled/online services are found, yet the inetd daemon is running, this is a finding.'
  desc 'fix', 'Disable the inetd service.

Procedure:
# svcadm disable inetd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29973r489790_chk'
  tag severity: 'medium'
  tag gid: 'V-227811'
  tag rid: 'SV-227811r603266_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29961r489791_fix'
  tag 'documentable'
  tag legacy: ['V-12005', 'SV-27426']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
