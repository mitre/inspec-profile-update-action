control 'SV-75237' do
  title 'The Google Search Appliance must support organizational requirements to enforce password encryption for transmission.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords during transmission.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Navigate to "Administration", select "SSL Settings".

Under "Other Settings" - If "Use HTTPS when serving both public and secure results" is checked, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "SSL Settings".

Under "Other Settings" - Enable option "Use HTTPS when serving both public and secure results".

Click Save.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61709r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60785'
  tag rid: 'SV-75237r1_rule'
  tag stig_id: 'GSAP-00-000565'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-66467r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
