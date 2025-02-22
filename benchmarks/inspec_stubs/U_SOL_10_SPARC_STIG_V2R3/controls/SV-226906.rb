control 'SV-226906' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29068r485005_chk'
  tag severity: 'medium'
  tag gid: 'V-226906'
  tag rid: 'SV-226906r603265_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29056r485006_fix'
  tag 'documentable'
  tag legacy: ['SV-27426', 'V-12005']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
