control 'SV-79761' do
  title 'The DataPower Gateway providing content filtering must protect against known and unknown types of Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis (traffic thresholds).'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.
 
This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic, rather than to the ALG device itself.'
  desc 'check', 'Type “Message Count Monitor” in nav search. Verify that Count Monitor exists. Check configuration of any active service to see that count monitor is in effect.

If no monitor is configured for each active service, this is a finding.'
  desc 'fix', 'Type “Message Count Monitor” in nav search. Create a new monitor with the desired limits. When configuring any service, activate the count monitor.'
  impact 0.7
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65899r1_chk'
  tag severity: 'high'
  tag gid: 'V-65271'
  tag rid: 'SV-79761r1_rule'
  tag stig_id: 'WSDP-AG-000099'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-71211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
