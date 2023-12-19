control 'SV-45886' do
  title 'Anonymous FTP accounts must not have a functional shell.'
  desc 'If an anonymous FTP account has been configured to use a functional shell, attackers could gain access to the shell if the account is compromised.'
  desc 'check', %q(Check the shell for the anonymous FTP account.

Procedure:
# grep "^ftp" /etc/passwd

This is a finding if the seventh field is empty (the entry ends with a ':') or if the seventh field does not contain one of the following:

/bin/false
/dev/null
/usr/bin/false
/bin/true
/sbin/nologin)
  desc 'fix', 'Configure anonymous FTP accounts to use a non-functional shell. The Yast ‘Security and Users’ > ‘User and Group Management’ module can be used to configure the account.  Or if necessary, edit the /etc/passwd file to remove any functioning shells associated with the ftp account and replace them with non-functioning shells, such as /bin/false.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43203r1_chk'
  tag severity: 'high'
  tag gid: 'V-4387'
  tag rid: 'SV-45886r1_rule'
  tag stig_id: 'GEN005000'
  tag gtitle: 'GEN005000'
  tag fix_id: 'F-39264r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
