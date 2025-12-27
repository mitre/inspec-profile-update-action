control 'SV-4287' do
  title 'A baseline of AIX files with the TCB bit set must be checked weekly.'
  desc 'If a baseline of files with the TCB bit set is not kept and checked weekly, the system could be compromised without the knowledge of any authority.'
  desc 'check', 'Perform the following command with no parameters to ensure the system is in trusted mode.

# /bin/tcbck

If TCB is not installed, the output will show an error code of 3001-101 and/or a text message indicating TCB is not installed.  If the output from the command indicates it is not in trusted mode, this is not reviewed.  Otherwise, check the root crontab to verify tcbck is executed weekly.  If it is not in the crontab, ask the SA if the check is run manually and to see the results of the check.'
  desc 'fix', 'Add tcbck command as a weekly cronjob with the output sent to the SA.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-2449r3_chk'
  tag severity: 'medium'
  tag gid: 'V-4287'
  tag rid: 'SV-4287r2_rule'
  tag stig_id: 'GEN000000-AIX00060'
  tag gtitle: 'GEN000000-AIX00060'
  tag fix_id: 'F-4198r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-001298']
  tag nist: ['SI-7 (1)']
end
