control 'SV-29653' do
  title 'The audit system must alert the SA when the audit storage volume approaches its capacity.'
  desc 'An accurate and current audit trail is essential for maintaining a record of system activity.  If the system fails, the SA must be notified and must take prompt action to correct the problem.

Minimally, the system must log this event and the SA will receive this notification during the daily system log review.  If feasible, active alerting (such as e-mail or paging) should be employed consistent with the site’s established operations management systems and procedures.'
  desc 'fix', 'Edit the AUDOMON_ARGS parameter of the /etc/rc.config.d/auditing file to include -w 90.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22375'
  tag rid: 'SV-29653r1_rule'
  tag stig_id: 'GEN002730'
  tag gtitle: 'GEN002730'
  tag fix_id: 'F-31780r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000143']
  tag nist: ['AU-5 (1)']
end
