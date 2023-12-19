control 'SV-35159' do
  title 'The system vulnerability assessment tool, host-based intrusion detection tool, and file integrity tool must notify the SA and the IAO of a security breach or a suspected security breach.'
  desc 'Timely notifications of potential security compromises minimize the potential damage.

Minimally, the system must log these events and the SA and the IAO will receive the notifications during the daily system log review.  If feasible, active alerting (such as e-mail or paging) should be employed consistent with the site’s established operations management systems and procedures.'
  desc 'check', 'Ask the SA if any security tool application is loaded on the system. Security tool applications include, but are not limited to, antivirus, file integrity, root kit detection, host-based intrusion detection, and vulnerability assessment tools.  For each security tool on the system, determine if the tool is configured to notify the IAO and SA of any detected security problem. If such notifications are not configured, this is a finding.'
  desc 'fix', 'Configure the security tools on the system to notify the IAO and SA when any security issues are detected.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36725r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12028'
  tag rid: 'SV-35159r1_rule'
  tag stig_id: 'GEN006560'
  tag gtitle: 'GEN006560'
  tag fix_id: 'F-32106r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECAT-1, ECAT-2'
  tag cci: ['CCI-000366', 'CCI-001266']
  tag nist: ['CM-6 b', 'SI-4 (7) (a)']
end
