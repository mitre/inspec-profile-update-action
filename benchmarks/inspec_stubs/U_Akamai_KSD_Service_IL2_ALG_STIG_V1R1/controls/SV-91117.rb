control 'SV-91117' do
  title 'Kona Site Defender providing content filtering must protect against known and unknown types of denial-of-service (DoS) attacks by employing rate-based attack prevention behavior analysis.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources may not be available to users during an attack.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks, which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.
 
This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic, rather than to the ALG device itself.'
  desc 'check', 'Confirm Kona Site Defender has rate controls enabled:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted for which product to use, select "Site Defender" and then "Continue".
5. Under the "Security Configurations" section, click on the most recent version under the "Production" column for the security configuration being reviewed.
6. The detailed "Security Configuration" page will load listing the protected host names and applicable policies.
7. Select the policy being reviewed.
8. Within the "Policy Details" section, verify the "Rate Controls" check box is selected.
9. Within the "Rate Controls" section, verify the action is set to "Deny" for each Adaptive Rule ID.

If "Rate Controls" is not selected, this is a finding.'
  desc 'fix', 'Configure the Kona Site Defender to enable rate controls.

The Akamai Professional Services team should be consulted to implement this Fix content due to the complexities involved. In most cases, this should be included in the SLA.

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted for which product to use, select "Site Defender" and then "Continue".
5. Under the "Security Configurations" section, click on the most recent version under the "Production" column for the security configuration being reviewed.
6. The detailed "Security Configuration" page will load listing the protected host names and applicable policies.
7. Click on the "Shared Resources" link.
8. Click on the "Rate Policies" link in the left hand column.
9. Click the plus shaped "+" icon to add a new Rate Policy.
10.  Follow the prompts to complete the process and click the "Save" button to complete the process.
OR
Contact the Akamai Professional Services team to implement the changes at 1-877-4-AKATEC (1-877-425-2832).'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76421'
  tag rid: 'SV-91117r1_rule'
  tag stig_id: 'AKSD-WF-000019'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-83099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
