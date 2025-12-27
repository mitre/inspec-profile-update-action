control 'SV-45873' do
  title 'The SMTP service must not have the Verify (VRFY) feature active.'
  desc 'The VRFY command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Determine if VRFY is disabled.

Procedure:
for sendmail:
# telnet localhost 25
vrfy root

If the command does not return a 500 error code of "command unrecognized", this is a finding.

or:
# grep -v "^#" /etc/mail/sendmail.cf |grep -i vrfy

Verify the VRFY command is disabled with an entry in the sendmail.cf file. The entry could be any one of "Opnovrfy", "novrfy", or "goaway", which could also have other options included, such as "noexpn". The "goaway" argument encompasses many things, such as "novrfy" and "noexpn".

If no setting to disable VRFY is found, this is a finding.

For Postfix:
Check if the VRFY command has been disabled:
# postconf disable_vrfy_command

If the command output is not “disable_vrfy_command = yes”, this is a finding.'
  desc 'fix', 'For sendmail:
Add the "novrfy" flag to your sendmail in /etc/mail/sendmail.cf. 

Procedure:
Edit the definition of "confPRIVACY_FLAGS" in /etc/mail/sendmail.mc to include "novrfy".

Rebuild the sendmail.cf file with:
# make -C /etc/mail

Restart the sendmail service.
# service sendmail restart

for Postfix:
Use the postconf utility to disable the VRFY command:
# postconf -ev disable_vrfy_command=yes

Restart the postfix service:
# rcpostfix restart'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43190r1_chk'
  tag severity: 'low'
  tag gid: 'V-4693'
  tag rid: 'SV-45873r1_rule'
  tag stig_id: 'GEN004680'
  tag gtitle: 'GEN004680'
  tag fix_id: 'F-39251r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
