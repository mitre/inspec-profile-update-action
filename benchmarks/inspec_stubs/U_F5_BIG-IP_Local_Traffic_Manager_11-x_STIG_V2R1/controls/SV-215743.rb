control 'SV-215743' do
  title 'The BIG-IP Core implementation must be configured to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to publicly accessible applications.'
  desc %q(Display of a standardized and approved use notification before granting access to the publicly accessible network element ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

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

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services off-loaded from the application. Publicly accessed systems are used in DoD to provide benefit information, pay information, or public services. There may also be self-registration and authorization services provided by these gateways.)
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to publicly accessible applications.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an access policy to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to publicly accessible applications.

If the BIG-IP Core is not configured to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the publicly accessible systems, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the APM module to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to publicly accessible applications.

Apply the APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to publicly accessible applications.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16935r291042_chk'
  tag severity: 'low'
  tag gid: 'V-215743'
  tag rid: 'SV-215743r557356_rule'
  tag stig_id: 'F5BI-LT-000027'
  tag gtitle: 'SRG-NET-000043-ALG-000024'
  tag fix_id: 'F-16933r291043_fix'
  tag 'documentable'
  tag legacy: ['V-60267', 'SV-74697']
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
