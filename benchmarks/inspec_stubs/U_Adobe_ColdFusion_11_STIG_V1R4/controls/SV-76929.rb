control 'SV-76929' do
  title 'ColdFusion must have Sandbox Security enabled.'
  desc 'Application isolation allows multiple applications to run on the same hosting operating system, web server and application server.  Typical reasons to isolate applications are to separate different application user bases, data security levels, protect application resources, and to give least privileges to each application to system resources.  Application isolation will also contain an application that has been compromised from compromising other hosted applications. 

To allow sandboxing to be implemented, the feature must be enabled.'
  desc 'check', 'Within the Administrator Console, navigate to the "Sandbox Security" page under the "Security" menu.

If "Enable ColdFusion Sandbox Security" is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Sandbox Security" page under the "Security" menu.  Check "Enable ColdFusion Sandbox Security" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62439'
  tag rid: 'SV-76929r1_rule'
  tag stig_id: 'CF11-03-000114'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-68359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
