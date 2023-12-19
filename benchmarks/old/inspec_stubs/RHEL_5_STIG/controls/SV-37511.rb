control 'SV-37511' do
  title 'The SMTP service must not have the Verify (VRFY) feature active.'
  desc 'The VRFY command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'fix', 'Add the "novrfy" flag to your sendmail in /etc/mail/sendmail.cf. 

Procedure:
Edit the definition of "confPRIVACY_FLAGS" in /etc/mail/sendmail.mc to include "novrfy".

Rebuild the sendmail.cf file with:
# make -C /etc/mail

Restart the sendmail service.
# service sendmail restart'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-4693'
  tag rid: 'SV-37511r1_rule'
  tag stig_id: 'GEN004680'
  tag gtitle: 'GEN004680'
  tag fix_id: 'F-31422r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
