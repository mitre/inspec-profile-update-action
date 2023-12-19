control 'SV-220071' do
  title 'The asetenv file YPCHECK variable must be set to true when NIS+ is configured.'
  desc 'If YPCHECK is not set to true in asetenv, then ypfiles may not be checked.'
  desc 'check', 'Perform the following to determine if ASET is configured to check NIS+.

	#	grep YPCHECK /usr/aset/asetenv

If  NIS+ is running and the YPCHECK variable is set to false, then this is a finding.'
  desc 'fix', 'Edit the ASET configuration and set YPCHECK to true on systems running NIS. (If NIS+ is configured, YPCHECK must only be set to false to avoid going into NIS compatibility mode.) Configure NIS to use YPCHECK.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21780r488153_chk'
  tag severity: 'medium'
  tag gid: 'V-220071'
  tag rid: 'SV-220071r603266_rule'
  tag stig_id: 'GEN000000-SOL00200'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-21779r488154_fix'
  tag 'documentable'
  tag legacy: ['SV-36750', 'V-954']
  tag cci: ['CCI-000366', 'CCI-000032']
  tag nist: ['CM-6 b', 'AC-4 (8) (a)']
end
