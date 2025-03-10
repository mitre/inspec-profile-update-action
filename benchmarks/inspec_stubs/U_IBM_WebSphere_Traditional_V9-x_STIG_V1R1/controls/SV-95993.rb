control 'SV-95993' do
  title 'The WebSphere Application Server must disable JSP class reloading.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.'
  desc 'check', 'From admin console, navigate to: Applications >> All applications >> [application name] >> JSP and JSP options.

If "JSP enable class reloading" is checked, this is a finding.'
  desc 'fix', 'To disable JSP reloading:

From the admin console, navigate to: Applications >> All applications >> [application name] >> JSP and JSP options.

Uncheck "JSP enable class reloading".'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81279'
  tag rid: 'SV-95993r1_rule'
  tag stig_id: 'WBSP-AS-000970'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-88061r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
