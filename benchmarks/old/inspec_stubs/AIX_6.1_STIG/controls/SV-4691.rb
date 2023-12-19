control 'SV-4691' do
  title 'The SMTP service must not have a uudecode alias active.'
  desc 'A common configuration for older Mail Transfer Agents (MTAs) includes an alias for the decode user.  All mail sent to this user is sent to the uudecode program, which automatically converts and stores files.  By sending mail to decode or uudecode aliases present on some systems, a remote attacker may be able to create or overwrite files on the remote host.  This could possibly be used to gain remote access.'
  desc 'check', 'Check the SMTP service for an active decode command.

Procedure:
# telnet localhost 25
decode

If the command does not return a 500 error code of command unrecognized, this is a finding.'
  desc 'fix', 'Disable mail aliases for decode and uudecode. If the /etc/aliases or /usr/lib/aliases (mail alias) file contains entries for these programs, remove them or disable them by placing # at the beginning of the line, and then executing the "newaliases" command. For more information on mail aliases, refer to the man page for aliases. Disabled aliases would be similar to the examples below:
# decode: |/usr/bin/uudecode
# uudecode: |/usr/bin/uuencode -d'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-653r2_chk'
  tag severity: 'high'
  tag gid: 'V-4691'
  tag rid: 'SV-4691r2_rule'
  tag stig_id: 'GEN004640'
  tag gtitle: 'GEN004640'
  tag fix_id: 'F-4619r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
