control 'SV-222633' do
  title 'A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Management (CM) process must be established.'
  desc "Software Configuration Management (SCM) is very important in tracking code releases, baselines, and managing access to the configuration management repository. An SCM plan or charter identifies what should be under configuration management control. Without an SCM plan and a CCB, application releases can't be tracked and vulnerabilities can be inserted intentionally or unintentionally into the code base of the application.

This requirement is intended to be applied to application developers or organizations responsible for code management or who have and operate an application CM repository."
  desc 'check', 'Interview the application representative and determine if application development is performed on site by the organization.

If application development is not done in house, the requirement is not applicable.

If so, determine if a CCB exists. Ask about the membership of the CCB, and identify the primary members. Ask if there is CCB charter documentation.

Interview the application representative and determine how often the CCB meets.

Ask if there is CCB charter documentation. The CCB charter documentation should indicate how often the CCB meets.

If there is no charter documentation, ask when the last time the CCB met and when was the last release of the application.

CCBs do not have to physically meet, and the CCB chair may authorize a release based on phone and/or e-mail conversations.

If there is no evidence of CCB activity or meetings prior to the last release cycle, this is a finding.'
  desc 'fix', 'Setup and maintain a Configuration Control Board.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24303r493807_chk'
  tag severity: 'medium'
  tag gid: 'V-222633'
  tag rid: 'SV-222633r508029_rule'
  tag stig_id: 'APSC-DV-003020'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24292r493808_fix'
  tag 'documentable'
  tag legacy: ['SV-84967', 'V-70345']
  tag cci: ['CCI-000366', 'CCI-001795']
  tag nist: ['CM-6 b', 'CM-9 b']
end
