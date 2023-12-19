control 'SV-45811' do
  title 'Network analysis tools must not be installed.'
  desc 'Network analysis tools allow for the capture of network traffic visible to the system.'
  desc 'check', 'Determine if any network analysis tools are installed.

Procedure:
# find / -name ethereal
# find / -name wireshark
# find / -name tshark
# find / -name netcat
# find / -name tcpdump
# find / -name snoop

If any network analysis tools are found, this is a finding.'
  desc 'fix', "Remove each network analysis tool binary from the system. Remove package items with a package manager, others remove the binary directly.

Procedure:

Find the binary file:
# find / -name <Item to be removed>

Find the package, if any, to which it belongs:
# rpm -qf <binary file>

Remove the package if it does not also include other software:
# rpm -e <package name>
# SuSEconfig


If the item to be removed is not in a package, or the entire package cannot be removed because of other software it provides, remove the item's binary file.
# rm <binary file>"
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43132r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12049'
  tag rid: 'SV-45811r1_rule'
  tag stig_id: 'GEN003865'
  tag gtitle: 'GEN003865'
  tag fix_id: 'F-39201r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
