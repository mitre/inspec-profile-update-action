control 'SV-4255' do
  title 'If the system boots from removable media, it must be stored in a safe or similarly secured container.'
  desc 'Storing the boot loader on removable media in an insecure location could allow a malicious user to modify the systems boot instructions or boot to an insecure operating system.'
  desc 'check', 'Ask the SA if the system boots from removable media. If so, ask if the boot media is stored in a secure container when not in use. If it is not, this is a finding.'
  desc 'fix', 'Store the system boot media in a secure container when not in use.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-2079r2_chk'
  tag severity: 'high'
  tag gid: 'V-4255'
  tag rid: 'SV-4255r2_rule'
  tag stig_id: 'GEN008680'
  tag gtitle: 'GEN008680'
  tag fix_id: 'F-4166r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'PESS-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
