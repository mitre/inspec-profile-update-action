control 'SV-80533' do
  title 'Trend Deep Security must synchronize with Active Directory on a daily (or AO-defined) basis.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', %q(Review the Trend Deep Security server to ensure synchronization occurs with Active Directory on a daily (or AO-defined) basis.

Under Administration >>  Scheduled Tasks, review the scheduled tasks listed for "Daily Sync Users".

If a task for syncing user's accounts with AD does not exist, this is a finding.)
  desc 'fix', 'Configure the Trend Deep Security server to synchronize with Active Directory on a daily (or AO-defined) basis.

Under Administration >> Scheduled Tasks, click "New".

From the "Type" drop down menu, select "Synchronize Users/Contacts".

Select "Daily", and click "Next".

Enter start date, start time, and select "Every Day".

Click "Next".

Enter a unique name for this scheduled task or leave the default.

Check the box for" Task Enabled", click "Finish".'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66687r2_chk'
  tag severity: 'medium'
  tag gid: 'V-66043'
  tag rid: 'SV-80533r1_rule'
  tag stig_id: 'TMDS-00-004515'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-72119r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
