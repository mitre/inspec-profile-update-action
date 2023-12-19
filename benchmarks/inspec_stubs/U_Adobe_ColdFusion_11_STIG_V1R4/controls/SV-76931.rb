control 'SV-76931' do
  title 'ColdFusion must have Sandboxes defined for application execution.'
  desc 'Application isolation allows multiple applications to run on the same hosting operating system, web server and application server.  Typical reasons to isolate applications are to separate different application user bases, data security levels, protect application resources, and to give least privileges to each application to system resources.  Application isolation will also contain an application that has been compromised from compromising other hosted applications.

To implement sandboxing, sandboxes must be setup to separate applications.  Enabling the feature without implementing sandboxes does not secure the system.'
  desc 'check', 'Within the Administrator Console, navigate to the "Sandbox Security" page under the "Security" menu.  Sandboxes should be setup for the Administrator Console and any other hosted applications.  The Administrator Console must have its own sandbox separate from the other hosted applications.

If there are no sandboxes implemented for the Administrator Console and the other hosted applications, this is a finding.'
  desc 'fix', 'Navigate to the "Sandbox Security" page under the "Security" menu.  Create sandboxes for the applications to operate within and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63245r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62441'
  tag rid: 'SV-76931r1_rule'
  tag stig_id: 'CF11-03-000115'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-68361r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
