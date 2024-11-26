control 'SV-220051' do
  title 'The SMTP service must not have a uudecode alias active.'
  desc 'A common configuration for older Mail Transfer Agents (MTAs) includes an alias for the decode user. All mail sent to this user is sent to the uudecode program, which automatically converts and stores files. By sending mail to decode or uudecode aliases present on some systems, a remote attacker may be able to create or overwrite files on the remote host. This could possibly be used to gain remote access.'
  desc 'check', 'Check the SMTP service for an active decode command.

Procedure:
# telnet localhost 25
decode

If the command does not return a 500 error code of command unrecognized, this is a finding.

If telnet is unavailable for testing, check for the existence of the decode and uudecode aliases in the sendmail aliases file.

Find the active sendmail aliases file.
# grep AliasFile /etc/mail/sendmail.cf
(The aliases file is usually at /etc/mail/aliases)
Look for decode aliases in the aliases file.
# grep decode /etc/mail/aliases

If there is an uncommented decode or uudecode alias in the aliases file, this is a finding.'
  desc 'fix', 'Comment out active decode and uudecode aliases in the aliases file.

# vi /usr/mail/aliases

Activate updated aliases file.

# newaliases'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21760r485147_chk'
  tag severity: 'high'
  tag gid: 'V-220051'
  tag rid: 'SV-220051r603265_rule'
  tag stig_id: 'GEN004640'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-21759r485148_fix'
  tag 'documentable'
  tag legacy: ['V-4691', 'SV-42312']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
