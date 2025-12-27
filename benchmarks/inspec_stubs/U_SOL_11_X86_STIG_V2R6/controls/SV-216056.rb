control 'SV-216056' do
  title 'The TFTP service daemon must not be installed unless required.'
  desc 'TFTP is an insecure protocol.'
  desc 'check', 'Determine if the TFTP package is installed.

# pkg list service/network/tftp

If an installed package named "/service/network/tftp" is listed and not required for operations, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall install/installadm
# pfexec pkg uninstall service/network/tftp'
  impact 0.7
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17294r372550_chk'
  tag severity: 'high'
  tag gid: 'V-216056'
  tag rid: 'SV-216056r603268_rule'
  tag stig_id: 'SOL-11.1-020140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17292r372551_fix'
  tag 'documentable'
  tag legacy: ['V-47913', 'SV-60785']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
