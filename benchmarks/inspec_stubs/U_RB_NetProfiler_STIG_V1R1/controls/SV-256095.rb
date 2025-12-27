control 'SV-256095' do
  title 'The Riverbed NetProfiler must be configured to run an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', "Go to System >> Update. 

Verify the current version is higher than 10.0.0 and currently supported by the vendor by checking the vendor's website (support.riverbed.com). 

If this is not true, this is a finding."
  desc 'fix', %q(Check the vendor's website (support.riverbed.com) to verify the current version installed on the NetProfiler appliance is supported. 

Go to System >> Update. 

Under "Add a different update version", select the" Update File:" radio button, click "Browse", find the update downloaded from a DOD authorized source, and select "Update Now".)
  impact 0.7
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59769r882791_chk'
  tag severity: 'high'
  tag gid: 'V-256095'
  tag rid: 'SV-256095r882793_rule'
  tag stig_id: 'RINP-DM-000063'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-59712r882792_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
