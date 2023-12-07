control 'SV-38867' do
  title 'Proxy ARP must not be enabled on the system.'
  desc 'Proxy ARP allows a system to respond to ARP requests on one interface on behalf of hosts connected to another interface.  If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'Determine if the system has proxy ARP enabled.

Check Content:  
Check the system for non-local published ARP entries.
# arp -a
If any entries are listed as published, this is a finding.'
  desc 'fix', 'Remove any non-local published ARP entries.
# arp -d < host >

Check system initialization scripts for any commands configuring published ARP entries (such as "arp -s <host> <addr> pub") and remove them.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37860r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22415'
  tag rid: 'SV-38867r1_rule'
  tag stig_id: 'GEN003608'
  tag gtitle: 'GEN003608'
  tag fix_id: 'F-33121r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
