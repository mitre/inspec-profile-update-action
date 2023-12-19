control 'SV-216293' do
  title 'The UUCP service daemon must not be installed unless required.'
  desc 'UUCP is an insecure protocol.'
  desc 'check', 'Determine if the UUCP package is installed.

# pkg list /service/network/uucp

If an installed package named "/service/network/uucp" is listed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall /service/network/uucp'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17529r370967_chk'
  tag severity: 'low'
  tag gid: 'V-216293'
  tag rid: 'SV-216293r603267_rule'
  tag stig_id: 'SOL-11.1-020160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17527r370968_fix'
  tag 'documentable'
  tag legacy: ['SV-60789', 'V-47917']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
