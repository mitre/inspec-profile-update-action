control 'SV-255950' do
  title 'The Arista network device must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DOD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.

'
  desc 'check', %q(Verify the Arista network device is configured to present a DOD-approved banner that is formatted in accordance with DTM-08-060.

Verify the Arista device uses the following verbiage for applications that can accommodate banners of 1300 characters by using the following command:

switch#show configuration | section banner
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't."

If the Arista device does not display such a banner, this is a finding.)
  desc 'fix', "Configure the Arista network device to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the device.

switch(config)#banner login
Enter TEXT message. 
<Insert banner here>
Type 'EOF' on its own line to end."
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59626r882190_chk'
  tag severity: 'medium'
  tag gid: 'V-255950'
  tag rid: 'SV-255950r882192_rule'
  tag stig_id: 'ARST-ND-000130'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-59569r882191_fix'
  tag satisfies: ['SRG-APP-000068-NDM-000215', 'SRG-APP-000069-NDM-000216']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
