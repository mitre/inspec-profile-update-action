control 'SV-252578' do
  title 'IBM Aspera Faspex must be configured to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the system.'
  desc %q(Display of a standardized and approved use notification before granting access to the network ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist. This requirement applies to network elements that have the concept of a user account and have the login function residing on the network element.

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

This policy only applies to ALGs (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.

)
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify the IBM Aspera Faspex default webpage displays the Standard Mandatory DoD-approved Notice and Consent Banner.

Using a web browser, go to the default IBM Aspera Faspex website. 

If the Standard Mandatory DoD-approved Notice and Consent Banner is not present, this is a finding.'
  desc 'fix', 'Configure the IBM Aspera Faspex default webpage to display the Standard Mandatory DoD-approved Notice and Consent Banner.

- Log in to IBM Aspera Faspex as an administrative user.
- Go to Server >> Notifications >> Login Announcement and enter the approved language.'
  impact 0.3
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56034r817902_chk'
  tag severity: 'low'
  tag gid: 'V-252578'
  tag rid: 'SV-252578r817904_rule'
  tag stig_id: 'ASP4-FA-050130'
  tag gtitle: 'SRG-NET-000041-ALG-000022'
  tag fix_id: 'F-55984r817903_fix'
  tag satisfies: ['SRG-NET-000041-ALG-000022', 'SRG-NET-000043-ALG-000024']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
