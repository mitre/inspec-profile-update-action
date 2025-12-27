control 'SV-38489' do
  title 'All interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a user has a home directory defined that does not exist, the user may be given the / directory, by default, as the current working directory upon logon. This could create a Denial of Service because the user would not be able to perform useful tasks in this location.'
  desc 'check', 'Verify the consistency of the assigned home directories in the authentication database.
For Trusted Mode:
# authck -av

If any assigned home directory does not exist, this is a finding.

For SMSE:
# pwck

If any assigned home directory does not exist, this is a finding.'
  desc 'fix', 'Determine why the user home directory does not exist. Possible actions include: account deletion or disablement. If the account is determined to be valid, create the home directory either manually (mkdir directoryname, copy the skeleton files into the directory, chown account name for the new directory and the skeleton files) or via the HP SMH/SAM utility.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36334r3_chk'
  tag severity: 'low'
  tag gid: 'V-900'
  tag rid: 'SV-38489r2_rule'
  tag stig_id: 'GEN001460'
  tag gtitle: 'GEN001460'
  tag fix_id: 'F-31589r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
