control 'SV-104189' do
  title 'Symantec ProxySG providing user access control intermediary services must display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network.'
  desc %q(Display of a standardized and approved use notification before granting access to the network ensures that privacy and security notification verbiage used is consistent with applicable Federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. This requirement applies to network elements that have the concept of a user account and have the logon function residing on the network element.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for network elements that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't."

This policy only applies to ALGs (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.)
  desc 'check', 'Verify that the Standard Mandatory DoD Banner is configured.

1. Log on to the Web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, ensure that the first Web Access Layer (furthest left) contains a single rule with a "Notify User" Action that contains the DoD banner text.
4. Right-click the "Notify User" action, select "Edit", and verify that the correct banner is specified in the "Body" field.
5. Verify the banner contains the exact DoD text.


If Symantec ProxySG providing user access control intermediary services does not display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network, this is a finding.'
  desc 'fix', 'Configure the Standard Mandatory DoD Banner to be displayed.

1. Log on to the Web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, create a new Web Access Layer, positioned in front (farthest left) of all other existing Web Access Layers and perform the following:
i. Click "edit" and select "add rule". 
ii. Right-click the "Actions" field of the new rule and select "set". Click "New" and select "NotifyUser" from the list and click "OK".
iii. Input the correct banner text in the "Body" field and click "OK".
iv. Click File >> Install Policy on SG Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93421r2_chk'
  tag severity: 'medium'
  tag gid: 'V-94235'
  tag rid: 'SV-104189r2_rule'
  tag stig_id: 'SYMP-AG-000100'
  tag gtitle: 'SRG-NET-000041-ALG-000022'
  tag fix_id: 'F-100351r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
