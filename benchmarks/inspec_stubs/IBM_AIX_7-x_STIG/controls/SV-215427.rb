control 'SV-215427' do
  title 'The AIX DHCP client must not send dynamic DNS updates.'
  desc 'Dynamic DNS updates transmit unencrypted information about a system including its name and address and should not be used unless needed.'
  desc 'check', %q(If AIX does not use DHCP client, this is Not Applicable.

Determine if the system's DHCP client is configured to send dynamic DNS updates: 
# grep "^updateDNS" /etc/dhcpc.opt /etc/dhcpcd.ini 

If any lines are returned, this is a finding.)
  desc 'fix', %q(Configure the system's DHCP client to not send dynamic DNS updates. 

Remove or comment-out "updateDNS" lines from the "/etc/dhcpcd.ini" and "/etc/dhcpc.opt" files.)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16625r294732_chk'
  tag severity: 'medium'
  tag gid: 'V-215427'
  tag rid: 'SV-215427r508663_rule'
  tag stig_id: 'AIX7-00-003132'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16623r294733_fix'
  tag 'documentable'
  tag legacy: ['SV-101813', 'V-91715']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
