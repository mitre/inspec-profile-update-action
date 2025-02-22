control 'SV-20630' do
  title 'Annual procedural reviews must be conducted at the site.'
  desc 'A regular review of current email security policies and procedures is necessary to maintain the desired security posture of Email services. Policies and procedures should be measured against current Department of Defense (DoD) policy, Security Technical Implementation Guide (STIG) guidance, vendor-specific guidance and recommendations, and site-specific or other security policy.'
  desc 'check', 'Review the EDSP and implementation evidence showing that annual reviews of Email Services Information Assurance (IA) policy and procedures are done.

If procedures are followed annually or more frequently, this is not a finding.'
  desc 'fix', 'Document review procedures in the EDSP.  Include annual review schedules and plans to conduct them.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22671r5_chk'
  tag severity: 'medium'
  tag gid: 'V-18857'
  tag rid: 'SV-20630r3_rule'
  tag stig_id: 'EMG3-015 EMail'
  tag gtitle: 'EMG3-015 Procedural Review'
  tag fix_id: 'F-19565r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'DCAR-1'
end
