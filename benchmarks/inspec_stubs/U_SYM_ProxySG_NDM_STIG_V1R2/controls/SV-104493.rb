control 'SV-104493' do
  title 'Symantec ProxySG must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc %q(Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.

Configuration of the notice banner on for logon to the management console requires the configuration of a reverse proxy service and a policy associated with this service. Refer to the detailed documentation for information on configuration. https://origin-symwisedownload.symantec.com//resources/webguides/proxysg/certification/notice_consent_webguide/Notice_Consent_Banner.htm#Topics/create_banner.htm and click on "Create a Banner for the Management Console" or search for "Symantec Notice and Consent Banner Configuration Webguide" in Google and click on  "Create the Notice and Consent Banner". 

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'Verify the Standard DoD Banner is displayed:

1. Log on to the Web Management Console of the Symantec ProxySG and confirm that a banner is displayed that complies with the DoD requirement.
2. SSH into the command line interface of the Symantec ProxySG and confirm that a banner is displayed that complies with the DoD requirement.
3. Connect a computer to the serial port of the appliance and confirm that the DoD banner is displayed.

If Symantec ProxySG does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device, this is a finding.'
  desc 'fix', %q(Configure the Symantec ProxySG Management Console, SSH, and serial port to display the Standard Mandatory DoD Notice and Consent Banner in accordance with DoD policy before granting access to the device. Use the following verbiage for applications that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't."

To create an SSH logon banner: 
1. Log on to the ProxySG Web Management Console, click "Configuration," then "Authentication," then "SSH Inbound Connections".  
2. Enter the desired banner text into the "SSHv2 Welcome Banner" field, click "Apply". 

To create a web user interface banner:
1. Log on to the ProxySG Management Console.
2. Create a reverse proxy service for the Notice and Consent banner. 
3. Create the banner policy for the reverse proxy service realm using Visual Policy Manager. 

To create a banner for the serial port:
1. Log on to the Command Line Interface (CLI).
2. Enter privileged mode.
3. Enter the following commands:

#(config)serial-console
#(config serial-console)inline pre-authentication-terms EOF
<Add the banner line by line exactly as stated with no changes.>
EOF)
  impact 0.3
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93853r1_chk'
  tag severity: 'low'
  tag gid: 'V-94663'
  tag rid: 'SV-104493r1_rule'
  tag stig_id: 'SYMP-NM-000060'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-100781r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
