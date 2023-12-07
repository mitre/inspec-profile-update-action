control 'SV-4387' do
  title 'Anonymous FTP accounts must not have a functional shell.'
  desc 'If an anonymous FTP account has been configured to use a functional shell, attackers could gain access to the shell if the account is compromised.'
  desc 'fix', 'Configure anonymous FTP accounts to use a non-functional shell. If necessary, edit the /etc/passwd file to remove any functioning shells associated with the FTP account and replace them with non-functioning shells, such as, /dev/null.'
  impact 0.7
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'high'
  tag gid: 'V-4387'
  tag rid: 'SV-4387r2_rule'
  tag stig_id: 'GEN005000'
  tag gtitle: 'GEN005000'
  tag fix_id: 'F-4298r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
