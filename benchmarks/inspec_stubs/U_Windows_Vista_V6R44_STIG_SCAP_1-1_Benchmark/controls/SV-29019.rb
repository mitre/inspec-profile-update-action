control 'SV-29019' do
  title 'The Recovery Console SET command must be disabled.'
  desc 'The Recovery Console SET command allows environment variables to be set in the Recovery Console.  This permits access to all drives and folders and the copying of files to removable media which could expose sensitive information.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Recovery Console: Allow floppy copy and access to all drives and all folders" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-1158'
  tag rid: 'SV-29019r2_rule'
  tag gtitle: 'Recovery Console - SET Command'
  tag fix_id: 'F-66893r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
