control 'SV-7459' do
  title 'The site must have written procedures for the protection, handling, accounting, and use of NSA Type 1 products.'
  desc 'Written procedures provide assurance that personnel take the required steps to prevent loss of keys or other breaches of system security.'
  desc 'check', 'Interview IAO. Verify written operating procedures exist for the protection, handling, accounting, and use of NSA Type 1 certified WLAN products and keys in a SWLAN operational environment.'
  desc 'fix', 'Document procedures for the protection, handling, accounting, and use of NSA Type 1 certified WLAN products and keys.'
  impact 0.3
  ref 'DPMS Target L3 KOV-26 Talon'
  tag check_id: 'C-4017r1_chk'
  tag severity: 'low'
  tag gid: 'V-7075'
  tag rid: 'SV-7459r1_rule'
  tag stig_id: 'WIR0230'
  tag gtitle: 'Procedures for Type 1 SWLANs'
  tag fix_id: 'F-6771r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
