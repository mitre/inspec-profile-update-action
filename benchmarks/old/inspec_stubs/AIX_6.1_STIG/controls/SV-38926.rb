control 'SV-38926' do
  title 'The system must not have 6to4 enabled.'
  desc '6to4 is an IPv6 transition mechanism involving tunneling IPv6 packets encapsulated in IPv4 packets on an ad-hoc basis.  This is not a preferred transition strategy and increases the attack surface of the system.'
  desc 'check', 'Determine if there are any 6to4 tunnels configured on the system.

#ifconfig -a 

If there are any sit or cit adapters in the ifconfig listing, this is a finding.'
  desc 'fix', 'Remove the configuration for any 6to4 tunnels on the system. 
#ifconfig sit0 detach
#rmdev -dl sit0

#ifconfig cit0 detach
#rmdev -dl cit0

Set the startup script /etc/rc.net to call autoconf6 with the -6 argument to prevent setting up 6 to 4 tunnels.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37911r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22545'
  tag rid: 'SV-38926r1_rule'
  tag stig_id: 'GEN007780'
  tag gtitle: 'GEN007780'
  tag fix_id: 'F-33169r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
