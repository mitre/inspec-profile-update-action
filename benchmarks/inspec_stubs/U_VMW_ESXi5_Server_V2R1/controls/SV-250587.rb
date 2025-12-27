control 'SV-250587' do
  title 'SNMP communities, users, and passphrases must be changed from the default.'
  desc 'Whether active or inactive, default communities, users, and passwords must be changed to maintain security. A service running with default authenticators allows acquisition of data about the system and the network to potentially compromise the integrity of the system or network(s).'
  desc 'check', 'Disable lock down mode.
Enable the ESXi Shell. Login as root and check the snmp configuration file for default(s):
# egrep -i "community|communities" /etc/vmware/snmp.xml

If any community name or password is set to a default value such as public, private or password, this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'From the Power/v CLI, run the (below example) command: >
# vicfg-snmp.pl --server <hostname|IP address> --username <username> --password <password> -E -c <community_name>

In the above example, -E enables the VMware SNMP agent, and -c sets communities to the provided name.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54022r798758_chk'
  tag severity: 'medium'
  tag gid: 'V-250587'
  tag rid: 'SV-250587r798760_rule'
  tag stig_id: 'GEN005300-ESXI5-000099'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53976r798759_fix'
  tag 'documentable'
  tag legacy: ['V-39247', 'SV-51063']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
