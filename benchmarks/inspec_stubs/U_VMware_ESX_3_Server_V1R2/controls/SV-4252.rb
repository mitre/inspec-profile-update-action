control 'SV-4252' do
  title 'If LILO is the authorized boot loader for the system, a global password must be defined in /etc/lilo.conf.'
  desc 'If LILO has been approved for use, it must be password protected to prevent malicious booting into single user mode and to prevent booting of an insecure operating system.'
  desc 'check', 'Check for the password to precede the first image stanza in /etc/lilo.conf:

	#	more /etc/lilo.conf

password=””
			image=/boot/vmlinuz-2.4.20-6smp

If a password is not found, then this is a finding.'
  desc 'fix', 'Password protect LILO by including the password=password line to the global section of /etc/lilo.conf.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2076r2_chk'
  tag severity: 'high'
  tag gid: 'V-4252'
  tag rid: 'SV-4252r2_rule'
  tag stig_id: 'GEN000000-LNX00180'
  tag gtitle: 'GEN000000-LNX00180'
  tag fix_id: 'F-4163r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
