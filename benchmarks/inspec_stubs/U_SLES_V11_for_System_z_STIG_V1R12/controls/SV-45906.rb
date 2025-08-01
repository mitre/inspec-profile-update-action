control 'SV-45906' do
  title 'The TFTP daemon must be configured to vendor specifications, including a dedicated TFTP user account, a non-login shell such as /bin/false, and a home directory owned by the TFTP user.'
  desc 'If TFTP has a valid shell, it increases the likelihood someone could log on to the TFTP account and compromise the system.'
  desc 'check', 'Check the /etc/passwd file to determine if TFTP is configured properly.

Procedure:
Check if TFTP if used.
# grep disable /etc/xinetd.d/tftp
If the file does not exist or the returned line indicates "yes", then this is not a finding.
Otherwise, if the returned line indicates "no" then TFTP is enabled and must use a dedicated "tftp" user.

# grep user /etc/xinetd.d/tftp
If the returned line indicates a user other than the dedicated "tftp" user, this is a finding.

# grep tftp /etc/passwd

If a "tftp" user account does not exist and TFTP is active, this is a finding.

Check the user shell for the "tftp" user. If it is not /bin/false or equivalent, this is a finding.

Check the home directory assigned to the "tftp" user. If no home directory is set, or the directory specified is not dedicated to the use of the TFTP service, this is a finding.'
  desc 'fix', 'Configure TFTP to use a dedicated "tftp" user.

Procedure:
Create a dedicated "tftp" user account if none exists.
Assign a non-login shell to the "tftp" user account, such as /bin/false.
Assign a home directory to the "tftp" user account.
Edit /etc/xinetd.d/tftp to have "tftp" as the value of the "user" parameter.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43215r1_chk'
  tag severity: 'medium'
  tag gid: 'V-849'
  tag rid: 'SV-45906r1_rule'
  tag stig_id: 'GEN005120'
  tag gtitle: 'GEN005120'
  tag fix_id: 'F-39285r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
