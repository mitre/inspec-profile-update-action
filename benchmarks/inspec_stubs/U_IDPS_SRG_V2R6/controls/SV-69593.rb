control 'SV-69593' do
  title 'The IDPS must protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing anomaly-based attack detection.'
  desc 'If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks.

Detection components that use anomaly-based attack detection can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures.

This requirement applies to the communications traffic functionality of the IDPS as it pertains to handling communications traffic, rather than to the IDPS device itself.'
  desc 'check', 'Verify the IDPS protect against or limits the effects of known and unknown types of DoS attacks by employing, also known as anomaly-based detection.

If the device does not protect against or limit the effects of known and unknown types of DoS attacks by employing anomaly-based detection, this is a finding.'
  desc 'fix', 'Configure the IDPS to protect against or limit the effects of known and unknown types of DoS attacks by employing anomaly-based detection.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55969r4_chk'
  tag severity: 'medium'
  tag gid: 'V-55347'
  tag rid: 'SV-69593r2_rule'
  tag stig_id: 'SRG-NET-000362-IDPS-00197'
  tag gtitle: 'SRG-NET-000362-IDPS-00197'
  tag fix_id: 'F-60213r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
