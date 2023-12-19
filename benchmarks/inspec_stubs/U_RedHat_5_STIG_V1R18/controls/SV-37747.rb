control 'SV-37747' do
  title 'The system vulnerability assessment tool, host-based intrusion detection tool, and file integrity tool must notify the SA and the IAO of a security breach or a suspected security breach.'
  desc "Timely notifications of potential security compromises minimize the potential damage.

Minimally, the system must log these events, and the SA and the ISSO will receive the notifications during the daily system log review.  If feasible, active alerting (such as e-mail or paging) should be employed consistent with the site's established operations management systems and procedures."
  desc 'check', 'For each security tool on the system, determine if the tool is configured to notify the IAO and SA of any detected security problem. If such notifications are not configured, this is a finding.'
  desc 'fix', 'Configure the security tools on the system to notify the IAO and SA when any security issues are detected.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36944r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12028'
  tag rid: 'SV-37747r2_rule'
  tag stig_id: 'GEN006560'
  tag gtitle: 'GEN006560'
  tag fix_id: 'F-32209r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366', 'CCI-001266']
  tag nist: ['CM-6 b', 'SI-4 (7) (a)']
end
