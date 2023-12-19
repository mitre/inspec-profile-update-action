control 'SV-218564' do
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
  desc 'fix', 'Configure anonymous FTP accounts to use a non-functional shell. If necessary, edit the /etc/passwd file to remove any functioning shells associated with the ftp account and replace them with non-functioning shells, such as /dev/null.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20039r562786_chk'
  tag severity: 'high'
  tag gid: 'V-218564'
  tag rid: 'SV-218564r603259_rule'
  tag stig_id: 'GEN005000'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20037r562787_fix'
  tag 'documentable'
  tag legacy: ['V-4387', 'SV-63109']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
