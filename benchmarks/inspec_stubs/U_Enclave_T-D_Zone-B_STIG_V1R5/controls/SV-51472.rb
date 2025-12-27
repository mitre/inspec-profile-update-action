control 'SV-51472' do
  title 'Application code must go through a code review prior to deployment into DoD operational networks.'
  desc 'Prior to release of the application receiving an IATO for deployment into a DoD operational network, the application will have a thorough code review.  Along with the proper testing, the code review will specify flaws causing security, compatibility, or reliability concerns that may compromise the operational network.'
  desc 'check', "Determine whether there is a policy in place for code review prior to applications being deployed into a DoD operational network.  If a code review policy has not been established, this is a finding.

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Implement a code review policy for applications before deployment into DoD operational networks.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46813r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39614'
  tag rid: 'SV-51472r1_rule'
  tag stig_id: 'ENTD0130'
  tag gtitle: 'ENTD0130 - Code review not completed prior to application deployment.'
  tag fix_id: 'F-44666r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCSQ-1, ECSC-1, ECSD-1, ECSD-2'
end
