control 'SV-76881' do
  title 'ColdFusion logs must, at a minimum, be transferred simultaneously for interconnected systems and transferred  weekly for standalone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.  Protecting log data is important during a forensic investigation to ensure investigators can track and understand what may have occurred.  ColdFusion does not offer an automated mechanism to off-load logs, but ColdFusion does have the capability to create archive log files.  By using the archive capability, off-loading can be set up using a weekly scheduled task for standalone systems.  For interconnected systems, applications such as syslog on Linux can be used to off-load data simultaneously.'
  desc 'check', 'Interview the administrator to determine whether or not ColdFusion logs are transferred to another system weekly for standalone systems and simultaneously for interconnected systems.

If the logs are not transferred weekly for standalone systems and simultaneously for interconnected systems, this is a finding.'
  desc 'fix', 'Implement a strategy that transfers logs weekly for standalone systems and simultaneously for interconnected systems.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62391'
  tag rid: 'SV-76881r1_rule'
  tag stig_id: 'CF11-02-000079'
  tag gtitle: 'SRG-APP-000515-AS-000203'
  tag fix_id: 'F-68311r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
