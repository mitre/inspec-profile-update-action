control 'SV-849' do
  title 'The TFTP daemon must be configured to vendor specifications, including a dedicated TFTP user account, a non-login shell, such as /bin/false, and a home directory owned by the TFTP user.'
  desc 'If TFTP has a valid shell, it increases the likelihood of someone logging to the TFTP account and compromising the system.'
  desc 'check', 'Check the /etc/passwd file to determine if TFTP is configured properly.

Procedure:
# grep tftp /etc/passwd

If a TFTP user account does not exist and TFTP is active, this is a finding.

Check the user shell for the TFTP user. If it is not /bin/false or equivalent, this is a finding.

Check the home directory assigned to the TFTP user. If no home directory is set, or the directory specified is not dedicated to the use of the TFTP service, this is a finding.'
  desc 'fix', 'Create a TFTP user account if none exists.
Assign a non-login shell to the TFTP user account, such as /bin/false.
Assign a home directory to the TFTP user account.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-715r2_chk'
  tag severity: 'medium'
  tag gid: 'V-849'
  tag rid: 'SV-849r2_rule'
  tag stig_id: 'GEN005120'
  tag gtitle: 'GEN005120'
  tag fix_id: 'F-1003r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
