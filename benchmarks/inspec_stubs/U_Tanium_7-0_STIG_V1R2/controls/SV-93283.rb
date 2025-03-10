control 'SV-93283' do
  title 'The Tanium endpoint must have the Tanium Servers public key in its installation, which will allow it to authenticate and uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect locally, remotely, or through a network to an endpoint device (including but not limited to workstations, printers, servers [outside a datacenter], VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific preauthorized devices can access the system.

'
  desc 'check', %q(The Tanium endpoint makes a connection to the Tanium Server, the endpoint's copy of the Tanium Server's public key is used to verify the validity of the registration day coming from the Tanium Server.

If any endpoint systems do not have the correct Tanium Server public key in its configuration, they will not perform any instructions from the Tanium Server and a record of those endpoints will be listed in the Tanium Server's System Status.

To validate, Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "System Status" tab.

Change "Show systems that have reported in the last:", enter "7" in the first field and select "Days" from the drop-down menu in the second field to determine if any endpoints connected with an invalid key.

If any systems are listed with "No" in the "Valid Key" column, this is a finding.)
  desc 'fix', 'For systems that do not have a valid key for the Tanium Server, redeploy the client software from Tanium using the Tanium Client Deployment Tool or work with the Tanium System Administrator to accomplish this.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78577'
  tag rid: 'SV-93283r1_rule'
  tag stig_id: 'TANS-CL-000001'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-85313r1_fix'
  tag satisfies: ['SRG-APP-000015', 'SRG-APP-000158', 'SRG-APP-000394']
  tag 'documentable'
  tag cci: ['CCI-000778', 'CCI-001453', 'CCI-001958']
  tag nist: ['IA-3', 'AC-17 (2)', 'IA-3']
end
