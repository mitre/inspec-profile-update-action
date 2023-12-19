control 'SV-218551' do
  title 'The SMTP service must not have the Verify (VRFY) feature active.'
  desc 'The VRFY command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Determine if VRFY is disabled.

Procedure:
# telnet localhost 25
vrfy root

If the command does not return a 500 error code of "command unrecognized", this is a finding.

or:
# grep -v "^#" /etc/mail/sendmail.cf |grep -i vrfy

Verify the VRFY command is disabled with an entry in the sendmail.cf file. The entry could be any one of "Opnovrfy", "novrfy", or "goaway", which could also have other options included, such as "noexpn". The "goaway" argument encompasses many things, such as "novrfy" and "noexpn".

If no setting to disable VRFY is found, this is a finding.'
  desc 'fix', 'Add the "novrfy" flag to your sendmail in /etc/mail/sendmail.cf. 

Procedure:
Edit the definition of "confPRIVACY_FLAGS" in /etc/mail/sendmail.mc to include "novrfy".

Rebuild the sendmail.cf file with:
# make -C /etc/mail

Restart the sendmail service.
# service sendmail restart'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20026r562753_chk'
  tag severity: 'low'
  tag gid: 'V-218551'
  tag rid: 'SV-218551r603259_rule'
  tag stig_id: 'GEN004680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20024r562754_fix'
  tag 'documentable'
  tag legacy: ['V-4693', 'SV-62859']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
