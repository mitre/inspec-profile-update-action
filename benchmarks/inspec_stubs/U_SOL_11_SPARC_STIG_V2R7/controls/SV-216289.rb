control 'SV-216289' do
  title 'The pidgin IM client package must not be installed.'
  desc 'Instant messaging is an insecure protocol.'
  desc 'check', 'Determine if the pidgin package is installed.

# pkg list communication/im/pidgin

If an installed package named communication/im/pidgin is listed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall communication/im/pidgin'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17525r370955_chk'
  tag severity: 'low'
  tag gid: 'V-216289'
  tag rid: 'SV-216289r603267_rule'
  tag stig_id: 'SOL-11.1-020120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17523r370956_fix'
  tag 'documentable'
  tag legacy: ['V-47909', 'SV-60781']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
