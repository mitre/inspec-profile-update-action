control 'SV-251236' do
  title 'Access to the Redis Enterprise control plane must be restricted.'
  desc 'If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.

The Redis administrative control plane helps facilitate configuration and application integrations with the database. Exposing the control plane application to any network interface that is available to non-administrative personnel leaves the server vulnerable to attempts to access the management application. To mitigate this risk, the management application must only be run on network interfaces tied to a dedicated management network or firewall rule to limit access to dedicated trusted machines.

Redis does not provide a configuration setting that can be used to restrict access to the administrative control plane, so firewall controls must be applied.'
  desc 'check', 'Review system documentation (SSP) and identify the documented management networks as well as the documented client networks. A management network can be defined through physical means or logical means to achieve network separation.

Check the network interface to verify the administrative console is on a separate management network interface.

If the control plane is set up to only be accessed via a defined management network, this is not a finding.

If a management network does not exist or network separation is not established, verify the control plane can only be accessed via trusted approved machines.

Review system documentation and obtain a list of approved machines for administrator use.

Check the firewall rules on the server. An example command is:
firewall-cmd --list-all

Check for rules showing that only the trusted and approved machines have access to the ports for the control plane (default is 8443) and REST API interface (default 9443). Below is an example of the output:
rich rules:
rule family="ipv4" source address="<trusted ip>" forward-port port="8443" protocol="tcp" to-port="80"
rule family="ipv4" source address="<trusted ip>" forward-port port="9443" protocol="tcp" to-port="80"

If access is not limited using a management network, network separation such as vlans, or a firewall rule, this a finding.'
  desc 'fix', %q(Configure a management network defined through physical or logical means to achieve network separation. Update system documentation (SSP) and identify the documented management networks as well as the documented client networks.

Configure the administrative control plane to only be accessible via the management network.

Alternatively, ensure a firewall rule is enabled on the network layer and the administrative control plane is only available through trusted and approved IPs.

Use firewalld (the host-based firewall service) on the server to set up a whitelist of IPs that it will accept to use the control plane and REST API ports. The default for these are 8443 and 9443. Below is an example:
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="<Trusted IP address>" port protocol="tcp" port="8443" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="<Trusted IP address>" port protocol="tcp" port="9443" accept'

Restart the firewall to save the rule:
systemctl restart firewalld)
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54671r806420_chk'
  tag severity: 'high'
  tag gid: 'V-251236'
  tag rid: 'SV-251236r806422_rule'
  tag stig_id: 'RD6X-00-010150'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-54625r806421_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
