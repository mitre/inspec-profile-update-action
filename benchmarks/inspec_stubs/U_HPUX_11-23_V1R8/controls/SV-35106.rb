control 'SV-35106' do
  title 'Anonymous FTP accounts must not have a functional shell.'
  desc 'If an anonymous FTP account has been configured to use a functional shell, attackers could gain access to the shell if the account is compromised.'
  desc 'check', 'Check the shell for the anonymous FTP account.
# cat /etc/passwd | grep "^ftp" | cut -f 7,7 -d ":" | \\
egrep -c -i "\\/bin\\/false|\\/dev\\/null|\\/usr\\/bin\\/false|\\/bin\\/true|\\/sbin\\/nologin"

This is a finding if the seventh field is empty (the entry ends with a colon[:]) or if the seventh field does not contain one of the following:

/bin/false
/dev/null
/usr/bin/false
/bin/true
/sbin/nologin'
  desc 'fix', 'Configure anonymous FTP accounts to use a non-functional shell. If necessary, edit the /etc/passwd file to remove any functioning shells associated with the FTP account and replace them with non-functioning shells, such as /dev/null.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36588r1_chk'
  tag severity: 'high'
  tag gid: 'V-4387'
  tag rid: 'SV-35106r1_rule'
  tag stig_id: 'GEN005000'
  tag gtitle: 'GEN005000'
  tag fix_id: 'F-31956r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
