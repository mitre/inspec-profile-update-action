control 'SV-220052' do
  title 'The TFTP daemon must be configured to vendor specifications, including a dedicated TFTP user account, a non-login shell, such as /bin/false, and a home directory owned by the TFTP user.'
  desc 'If TFTP has a valid shell, it increases the likelihood of someone logging to the TFTP account and compromising the system.'
  desc 'check', 'Verify the tftp service is enabled.

# svcs tftp

If the tftp service is not installed or enabled, this check is not applicable.

Check the /etc/passwd file to determine if TFTP is configured properly.

Procedure:
# grep tftp /etc/passwd

If a "tftp" user account does not exist and TFTP is active, this is a finding.

Check the user shell for the "tftp" user. If it is not /bin/false or equivalent, this is a finding.

Check the home directory assigned to the "tftp" user. If no home directory is set, or the directory specified is not dedicated to the use of the TFTP service, this is a finding.'
  desc 'fix', 'Create a TFTP user account if none exists.
Assign a non-login shell to the TFTP user account, such as /bin/false.
Assign a home directory to the TFTP user account.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21761r485207_chk'
  tag severity: 'medium'
  tag gid: 'V-220052'
  tag rid: 'SV-220052r603265_rule'
  tag stig_id: 'GEN005120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21760r485208_fix'
  tag 'documentable'
  tag legacy: ['V-849', 'SV-39825']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
