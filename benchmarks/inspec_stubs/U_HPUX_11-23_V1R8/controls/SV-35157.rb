control 'SV-35157' do
  title 'The TFTP daemon must be configured to vendor specifications, including a dedicated TFTP user account, a non-login shell such as /bin/false, and a home directory owned by the TFTP user.'
  desc 'If TFTP has a valid shell, it increases the likelihood that someone could logon to the TFTP account and compromise the system.'
  desc 'check', 'Check the /etc/passwd file to determine if TFTP is configured properly.

Procedure:
# grep tftp /etc/passwd

If a TFTP user account does not exist and TFTP is active, this is a finding.

Check the user shell for the TFTP user. If it is not /bin/false or equivalent, this is a finding.

Check the home directory assigned to the TFTP user. If no home directory is set, or the directory specified is not dedicated to the use of the TFTP service, this is a finding.'
  desc 'fix', 'Create a tftp user account if none exists.
Assign a non-login shell to the tftp user account, such as /usr/bin/false.
Assign/create the tftp user account home directory where/as necessary. 
Ensure the home directory is owned by the tftp user.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-715r2_chk'
  tag severity: 'medium'
  tag gid: 'V-849'
  tag rid: 'SV-35157r1_rule'
  tag stig_id: 'GEN005120'
  tag gtitle: 'GEN005120'
  tag fix_id: 'F-31962r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
