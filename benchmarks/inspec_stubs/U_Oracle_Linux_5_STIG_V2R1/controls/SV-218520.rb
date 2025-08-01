control 'SV-218520' do
  title 'Network analysis tools must not be installed.'
  desc 'Network analysis tools allow for the capture of network traffic visible to the system.

If the system is being used as a network analysis/troubleshooting system then these tools are allowed if documented.'
  desc 'check', 'Determine if any network analysis tools are installed.

Procedure:

# find / -name ethereal
# find / -name wireshark
# find / -name tshark
# find / -name nc
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

or
 
# yum remove <package name>

If the item to be removed is not in a package, or the entire package cannot be removed because of other software it provides, remove the item's binary file.

# rm <binary file>"
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19995r562684_chk'
  tag severity: 'medium'
  tag gid: 'V-218520'
  tag rid: 'SV-218520r603259_rule'
  tag stig_id: 'GEN003865'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19993r562685_fix'
  tag 'documentable'
  tag legacy: ['V-12049', 'SV-64029']
  tag cci: ['CCI-000305', 'CCI-000381']
  tag nist: ['CM-7 (2)', 'CM-7 a']
end
