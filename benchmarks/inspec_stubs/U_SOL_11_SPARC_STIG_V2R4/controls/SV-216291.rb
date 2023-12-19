control 'SV-216291' do
  title 'The TFTP service daemon must not be installed unless required.'
  desc 'TFTP is an insecure protocol.'
  desc 'check', 'Determine if the TFTP package is installed.

# pkg list service/network/tftp

If an installed package named "/service/network/tftp" is listed and not required for operations, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall install/installadm
# pfexec pkg uninstall service/network/tftp'
  impact 0.7
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17527r370961_chk'
  tag severity: 'high'
  tag gid: 'V-216291'
  tag rid: 'SV-216291r603267_rule'
  tag stig_id: 'SOL-11.1-020140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17525r370962_fix'
  tag 'documentable'
  tag legacy: ['SV-60785', 'V-47913']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
