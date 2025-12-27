control 'SV-226896' do
  title 'Proxy ARP must not be enabled on the system.'
  desc 'Proxy ARP allows a system to respond to ARP requests on one interface on behalf of hosts connected to another interface.  If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'Determine if the system has non-local published ARP entries.

Procedure:
# arp -a

If any entries have the flag P and no flag L, they are non-local published entries, and this is a finding.'
  desc 'fix', 'Remove non-local published ARP entries from the system.

Procedure:
# arp -d <host>

Check system initialization files for any commands creating published ARP entries (such as "arp -s <host> <ether> pub" or "arp -f") and removing them.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29058r484972_chk'
  tag severity: 'medium'
  tag gid: 'V-226896'
  tag rid: 'SV-226896r603265_rule'
  tag stig_id: 'GEN003608'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29046r484973_fix'
  tag 'documentable'
  tag legacy: ['V-22415', 'SV-29603']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
