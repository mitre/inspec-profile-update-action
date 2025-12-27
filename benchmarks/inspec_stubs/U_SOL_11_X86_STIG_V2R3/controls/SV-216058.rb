control 'SV-216058' do
  title 'The UUCP service daemon must not be installed unless required.'
  desc 'UUCP is an insecure protocol.'
  desc 'check', 'Determine if the UUCP package is installed.

# pkg list /service/network/uucp

If an installed package named "/service/network/uucp" is listed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall /service/network/uucp'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17296r372556_chk'
  tag severity: 'low'
  tag gid: 'V-216058'
  tag rid: 'SV-216058r603268_rule'
  tag stig_id: 'SOL-11.1-020160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17294r372557_fix'
  tag 'documentable'
  tag legacy: ['V-47917', 'SV-60789']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
