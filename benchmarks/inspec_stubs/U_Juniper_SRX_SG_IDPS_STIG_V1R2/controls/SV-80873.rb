control 'SV-80873' do
  title 'The Juniper Networks SRX Series Gateway IDPS must enforce approved authorizations by restricting or blocking the flow of harmful or suspicious communications traffic within the network as defined in the PPSM CAL and vulnerability assessments.'
  desc 'The flow of all communications traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Restricting the flow of communications traffic, also known as Information flow control, regulates where information is allowed to travel as opposed to who is allowed to access the information and without explicit regard to subsequent accesses to that information.

The IDPS will include policy filters, rules, signatures, and behavior analysis algorithms that inspects and restricts traffic based on the characteristics of the information and/or the information path as it crosses internal network boundaries. The IDPS monitors for harmful or suspicious information flows and restricts or blocks this traffic based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

The PPSM CAL addresses internal network boundaries restrictions based on traffic type and content such as ports, protocols and services. The Juniper SRX denies all traffic.

IDPS inspection will only be performed on the traffic matching the security policies where IDPS is enabled.'
  desc 'check', "Review the list of authorized Junos applications, endpoints, services, and protocols that are installed on the PPSM CAL.

Use the following command to show the IDP-specific policies:

[edit]
show security idp

Next, use the show security policies command to display a summary of all the security policies.

[edit]
show security policies

Note: Also inspect the organization's central events log server (e.g., syslog server) for Deny events that match the restrictions in the PPSM CAL.

If security policies do not exist to block or restrict communications traffic that is identified as harmful or suspicious by the PPSM and vulnerability assessment, this is a finding."
  desc 'fix', 'Specify an active IDP policy prior to enabling IDP within a security policy. To configure the active IDP policy, execute the following command in configuration mode:

[edit]
set security idp active-policy <policy name>

Configure Security Policies for IDP inspection. Once the IDP policy is configured, IDP must be enabled on a security policy in order for IDP inspection to be performed. IDP inspection will only be performed on the traffic matching the security policies where IDP is enabled.

To enable IDP on a security policy, enter the following command:

[edit]
set security policies from-zone <FROM ZONE NAME> to-zone <TO ZONE NAME> policy <POLICY
NAME> then permit application-services idp'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67029r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66383'
  tag rid: 'SV-80873r1_rule'
  tag stig_id: 'JUSX-IP-000002'
  tag gtitle: 'SRG-NET-000018-IDPS-00018'
  tag fix_id: 'F-72459r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
