control 'SV-91115' do
  title 'Kona Site Defender must not strip origin-defined HTTP session headers.'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides the opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

Non-organizational users will be uniquely identified and authenticated for all accesses other than accesses explicitly identified and documented by the organization when related to the use of anonymous access. Authorization requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of user identities is accomplished through the use of passwords, tokens, biometrics, or in the case of multifactor authentication, some combination thereof.

This control applies to application layer gateways that provide content filtering and proxy services on network segments (e.g., DMZ) that allow access by non-organizational users. It focuses on authentication requests to the proxied application for access to destination resources and policy filtering decisions rather than administrator and management functions.'
  desc 'check', 'Confirm Kona Site Defender is not stripping origin-defined HTTP session headers:

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Configure" tab and select "Site" under the "Property" section.
3. If prompted for which product to use, select "Site Defender" and then "Continue".
4. Click on the applicable configuration.
5. Click on the applicable version of the configuration.
6. Click the "View XML" button.
7. Search the XML text for the following fields and confirm that no origin session headers are being added or removed:
"edgeservices:modify-incoming-request.remove-header"
"edgeservices:modify-incoming-request.add-header"
"edgeservices:modify-incoming-response.remove-header"
"edgeservices:modify-incoming-response.add-header"
"edgeservices:modify-outgoing-request.remove-header"
"edgeservices:modify-outgoing-request.add-header"
"edgeservices:modify-outgoing-response.remove-header"
"edgeservices:modify-outgoing-response.add-header"

If Kona Site Defender is stripping origin-defined HTTP session headers, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to not modify origin-defined HTTP session headers:

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Configure" tab and select "Site" under the "Property" section.
3. If prompted for which product to use, select "Site Defender" and then "Continue".
4. Click on the applicable configuration.
5. Click on the applicable version of the configuration.
6. Search the "Property Configuration Settings" and remove any of the following behaviors that are modifying origin-defined HTTP session headers:
"Modify Incoming Request Header"
"Modify Incoming Response Header"
"Modify Outgoing Request Header"
"Modify Outgoing Response Header"
OR
Contact the Akamai Professional Services team to implement the changes at 1-877-4-AKATEC (1-877-425-2832).'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76419'
  tag rid: 'SV-91115r1_rule'
  tag stig_id: 'AKSD-WF-000018'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-83095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
