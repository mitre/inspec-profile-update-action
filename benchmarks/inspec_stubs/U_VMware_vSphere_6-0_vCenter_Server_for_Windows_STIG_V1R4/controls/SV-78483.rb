control 'SV-78483' do
  title 'Log files must be cleaned up after failed installations of the vCenter Server.'
  desc 'In certain cases, if the vCenter installation fails, a log file (with a name of the form “hs_err_pidXXXX”) is created that contains the database password in plain text. An attacker who breaks into the vCenter Server  could potentially steal this password and access the vCenter Database.'
  desc 'check', 'If at any time a vCenter Server installation fails, only the log files of format "hs_err_pid...." should be identified on the Windows host and deleted securely before putting the host into production. Determine if a site policy exists for handling failed installation cleanup of the Windows host prior to deployment. Using the Windows host search function, determine the existence of any log files of format "hs_err_pid".

If a file name of the format "hs_err_pid" is found, this is a finding.

If a site policy does not exist and/or is not followed, this is a finding.'
  desc 'fix', 'Develop a site policy for handling failed installation cleanup of the Windows host prior to deployment. Using the Windows host search function, determine the existence of any log files of format "hs_err_pid" and remove them.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63993'
  tag rid: 'SV-78483r1_rule'
  tag stig_id: 'VCWN-06-000028'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69923r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
