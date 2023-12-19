control 'SV-38703' do
  title 'The system must not have the bootp service active.'
  desc 'The bootp service is used for Network Installation Management (NIM) and remote booting of systems.  The bootp service should not be active unless it is needed for NIM servers or booting remote systems.  Running unnecessary services increases the attack vector of the system.'
  desc 'check', 'Check the /etc/inetd.conf file for active bootp service.

# grep bootp /etc/inetd.conf |grep -v \\#

If the bootp service is not disabled, this is a finding.'
  desc 'fix', 'Disable the bootp service from /etc/inetd.conf.

Edit /etc/inetd.conf and comment out bootp service line. 

Restart the inetd service.   
#refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29499'
  tag rid: 'SV-38703r1_rule'
  tag stig_id: 'GEN000000-AIX0300'
  tag gtitle: 'GEN000000-AIX0300'
  tag fix_id: 'F-33057r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
