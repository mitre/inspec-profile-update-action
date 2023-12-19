control 'SV-46344' do
  title 'The application pool must have a recycle time set.'
  desc 'Application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks.'
  desc 'check', 'Note: Recycling Application Pools can create an unstable environment in a 64-bit Sharepoint environment. If operational issues arise, with supporting documentation from the ISSO this check can be downgraded to a Cat III.

1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight the desired application pool and click Recycling... in the Action Pane.
4. Review the Fixed Intervals section. If both Regular time intervals and Specific time(s) are unchecked, this is a finding. If only Regular Time Intervals is checked and the value is set to 0, this is a finding.
NOTE: Do not click Recycle!'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an application pool and click Recycling... in the Action Pane.
4. Choose a fixed interval type of fixed time and/or specific time. If regular time interval is the only type chosen, then the value entered must be greater than 0.
NOTE: Do not click Recycle!'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32828r10_chk'
  tag severity: 'medium'
  tag gid: 'V-13704'
  tag rid: 'SV-46344r4_rule'
  tag stig_id: 'WA000-WI6020 IIS7'
  tag gtitle: 'WA000-WI6020'
  tag fix_id: 'F-28939r4_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
