control 'SV-37549' do
  title 'Anonymous FTP accounts must not have a functional shell.'
  desc 'If an anonymous FTP account has been configured to use a functional shell, attackers could gain access to the shell if the account is compromised.'
  desc 'check', %q(Check the shell for the anonymous FTP account.

Procedure:
# cat /etc/passwd | grep -i "^ftp:" | awk -F":" '{print$7}'

If the seventh field is empty (the entry ends with a ':') or if the seventh field does not contain one of the following, this is a finding:

/bin/false
/dev/null
/usr/bin/false
/bin/true
/sbin/nologin)
  desc 'fix', 'Configure anonymous FTP accounts to use a non-functional shell. If necessary, edit the /etc/passwd file to remove any functioning shells associated with the ftp account and replace them with non-functioning shells, such as /dev/null.'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36203r2_chk'
  tag severity: 'high'
  tag gid: 'V-4387'
  tag rid: 'SV-37549r2_rule'
  tag stig_id: 'GEN005000'
  tag gtitle: 'GEN005000'
  tag fix_id: 'F-31462r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
