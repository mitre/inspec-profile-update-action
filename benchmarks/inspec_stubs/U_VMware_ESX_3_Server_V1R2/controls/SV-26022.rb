control 'SV-26022' do
  title 'The audit system must alert the SA when the audit storage volume approaches its capacity.'
  desc 'An accurate and current audit trail is essential for maintaining a record of system activity.  If the system fails, the SA must be notified and must take prompt action to correct the problem.

Minimally, the system must log this event and the SA will receive this notification during the daily system log review.  If feasible, active alerting (such as email or paging) should be employed consistent with the site’s established operations management systems and procedures.'
  desc 'check', 'Determine if the audit system is configured to alert the SA when the audit storage volume approaches capacity.  If it does not, this is a finding.'
  desc 'fix', 'Configure the audit system to alert the SA when the audit storage volume approaches capacity.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29208r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22375'
  tag rid: 'SV-26022r1_rule'
  tag stig_id: 'GEN002730'
  tag gtitle: 'GEN002730'
  tag fix_id: 'F-26228r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000143']
  tag nist: ['AU-5 (1)']
end
