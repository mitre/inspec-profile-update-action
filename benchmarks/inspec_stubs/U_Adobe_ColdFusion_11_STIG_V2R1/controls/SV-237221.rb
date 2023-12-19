control 'SV-237221' do
  title 'ColdFusion must encrypt patch retrieval.'
  desc 'Checking for patches and downloading those patches for installation must be done through an encrypted connection to protect the patch from modification during transmission and to avoid spoofed updates.'
  desc 'check', 'If the Administrator Console is used to perform patch retrieval, navigate to the "Updates" page under the "Server Update" menu within the console and review the setting "Site URL" within the "Settings" tab.

If the URL is not prefixed by https://, this is a finding.

If a manual process is used to retrieve patches, verify that a documented process is in place that includes using an encrypted method to download the patches, e.g., VPN tunneling, Secure Copy (SCP), etc.

If there is not a documented process or the process does not include an encrypted method to download patches, this is a finding.'
  desc 'fix', 'If the Administrator Console is used for patch retrieval, navigate to the "Updates" page under the "Server Update" menu within the console.  Locate the "Site URL" setting on the "Settings" tab.  Update the URL used for updates to be prefixed with https:// so that the communication is encrypted and select the "Submit Changes" button.

If a manual process is used to retrieve patches, document the process to retrieve the patches that uses an encrypted method to download the patches, e.g., VPN tunneling, Secure Copy (SCP), etc.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40440r641756_chk'
  tag severity: 'medium'
  tag gid: 'V-237221'
  tag rid: 'SV-237221r641758_rule'
  tag stig_id: 'CF11-05-000198'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-40403r641757_fix'
  tag 'documentable'
  tag legacy: ['SV-77005', 'V-62515']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
