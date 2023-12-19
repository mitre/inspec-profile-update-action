control 'SV-69591' do
  title 'The IDPS must protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis.'
  desc 'If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.

This requirement applies to the communications traffic functionality of the IDPS as it pertains to handling communications traffic, rather than to the IDPS device itself.'
  desc 'check', 'Verify the IDPS protects against or limits the effects of known and unknown types of DoS attacks by employing rate-based attack prevention behavior analysis.

If the device does not protect against or limit the effects of known and unknown types of DoS attacks by employing rate-based attack prevention behavior analysis, this is a finding.'
  desc 'fix', 'Configure the IDPS to protect against or limit the effects of known and unknown types of DoS attacks by employing rate-based attack prevention behavior analysis.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55345'
  tag rid: 'SV-69591r1_rule'
  tag stig_id: 'SRG-NET-000362-IDPS-00196'
  tag gtitle: 'SRG-NET-000362-IDPS-00196'
  tag fix_id: 'F-60211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
