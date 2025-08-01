control 'SV-12537' do
  title 'The LILO Boot Loader password is not encrypted.'
  desc 'On newer linux systems, the lilo password can be hashed in a separate file.  To determine if the lilo password is encrypted perform the following:

	# grep password /etc/lilo.conf

If the returned line contains password=””, then perform the following:

	# more /etc/lilo.conf.crc

If the file does not exist, this is a finding.'
  desc 'check', 'On newer Linux systems, the LILO password can be hashed in a separate file.  To determine if the LILO password is encrypted perform the following:

	# grep password /etc/lilo.conf

If the returned line contains password=””, then perform the following:

	# more /etc/lilo.conf.crc

If the system uses the LILO boot loader, and the file does not exist, this is a finding.'
  desc 'fix', 'Configure LILO for encrypted passwords.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7999r2_chk'
  tag severity: 'high'
  tag gid: 'V-12036'
  tag rid: 'SV-12537r2_rule'
  tag stig_id: 'LNX00200'
  tag gtitle: 'LILO Boot Loader Encrypted Password'
  tag fix_id: 'F-11293r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
