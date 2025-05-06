control 'SV-36045' do
  title 'Mobile users must complete required training annually.'
  desc 'Users are the first line of security controls for mobile device systems. They must be trained in using mobile device security controls or the system could be vulnerable to attack. If training is not renewed on an annual basis, users may not be informed of new security procedures or may forget previously trained procedures, which could lead to an exposure of sensitive DoD information.'
  desc 'check', 'This requirement applies to mobile operating system (OS) mobile devices.

All mobile device users must receive required training annually. If training records do not show users receiving required training at least annually, this is a finding.'
  desc 'fix', 'Complete required training annually for all mobile device users.'
  impact 0.3
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-35165r8_chk'
  tag severity: 'low'
  tag gid: 'V-28317'
  tag rid: 'SV-36045r6_rule'
  tag stig_id: 'WIR-SPP-006-02'
  tag gtitle: 'Annual training required'
  tag fix_id: 'F-30413r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
