control 'SV-85987' do
  title 'The CA API Gateway providing content filtering must block outbound traffic containing known and unknown Denial of Service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.'
  desc %q(DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of an ALG at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The ALG must include protection against DoS attacks that originate from inside the enclave, which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

To comply with this requirement, the ALG must monitor outbound traffic for indications of known and unknown DoS attacks. Audit log capacity management, along with techniques that prevent the logging of redundant information during an attack, also guard against DoS attacks.

The CA API Gateway must enable an inbound rate limit in an effort to provide safeguards against DoS attacks. By default, this is not turned on and will need to be enabled either in Global Policy or within each Registered Service. Additionally, a quota can be inserted within a Registered Service's policy to verify that any request exceeding the quota for an authenticated user, client IP, etc. will be denied access to the Registered Service. Furthermore, a message size limiter can be inserted into a policy to limit the size of any request being received or response being sent.)
  desc 'check', %q(Open the CA API Gateway - Policy Manager. 

Check the lower-left corner of the CA API Gateway - Policy Manager to see if a Global Policy is set that includes an "Apply Rate Limit" Assertion. (Global policies are displayed with a green icon beside their name.) 

If the policy does not exist, this is a finding. 

If it does exist, verify the Rate Limits are set to meet the organization's security requirements for DoS attacks. 

Also check each Registered Service requiring additional safeguards such as quota limits and message size limitation to verify the "Apply Throughput Quota" and "Limit Message Size" Assertions have been added and configured to meet organizational requirements. 

If they have not, this is also a finding.)
  desc 'fix', %q(Open the CA API Gateway - Policy Manager. 

Select "Tasks" from the main menu and choose "Create Policy". Give the policy a name and select "Global Policy Fragment" from the Policy Type drop-down menu. 

Select "message-received" from the Policy Tag drop-down menu and click "OK".

Drag the "Apply Rate Limit" Assertion into the newly created Global Policy Fragment. Set the "Maximum requests per second" and/or "Maximum concurrent requests" and/or "Limit each:" values to meet the organization's requirements to protect against DoS attacks. 

Click "Save and Activate”.

Also double-click each Registered Service requiring additional safeguards, such as quota limits message size limitations, to verify/add the "Apply Throughput Quota" and "Limit Message Size" Assertions and configure their settings in accordance with organizational requirements.)
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71363'
  tag rid: 'SV-85987r1_rule'
  tag stig_id: 'CAGW-GW-000370'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-77673r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
