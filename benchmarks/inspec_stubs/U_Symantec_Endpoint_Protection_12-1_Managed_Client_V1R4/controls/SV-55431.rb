control 'SV-55431' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for handling File Reputation lookup detections must be set to Leave alone (log only) if first action fails.'
  desc 'This setting is required for the weekly scan parameter Security Risks First Action policy. When a Security Risk is detected, the if the first action fails, the second action must be set to "Leave alone (log only)".'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Insight Lookup tab, Malicious files -> Ensure If first action fails is set to "Leave alone (log only)".

Criteria:  If first action fails is not set to "Leave alone (log only)", this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Insight Lookup tab, Malicious files -> Set If first action fails to "Leave alone (log only)".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48974r4_chk'
  tag severity: 'medium'
  tag gid: 'V-42703'
  tag rid: 'SV-55431r2_rule'
  tag stig_id: 'DTASEP048'
  tag gtitle: 'DTASEP048'
  tag fix_id: 'F-48288r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
