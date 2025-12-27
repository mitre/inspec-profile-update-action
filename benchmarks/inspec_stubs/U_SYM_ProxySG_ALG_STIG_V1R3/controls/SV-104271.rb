control 'SV-104271' do
  title 'Symantec ProxySG providing content filtering must protect against known and unknown types of denial-of-service (DoS) attacks by employing rate-based attack prevention behavior analysis.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks, which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.'
  desc 'check', 'View the denial-of-service attack detection/mitigation configuration.
 
1. SSH into the ProxySG console and type "enable".
2. Enter the correct password and type "config". 
3. Press "Enter" and type "show attack-detection configuration". 
4. Verify that "client limits enabled" equals "true".

If Symantec ProxySG providing content filtering does not protect against known and unknown types of Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis, this is a finding.'
  desc 'fix', 'Configure denial-of-service attack detection/mitigation.
 
1. SSH into the ProxySG console and type "enable".
2. Enter the correct password and type "config". 
3. Press "Enter" and type "attack-detection".
4. Type "client", press "Enter", type "enable-limits", and press "Enter".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93503r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94317'
  tag rid: 'SV-104271r1_rule'
  tag stig_id: 'SYMP-AG-000520'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-100433r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
