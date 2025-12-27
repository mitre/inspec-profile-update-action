control 'SV-75343' do
  title 'The Arista Multilayer Switch must employ AAA service to centrally manage authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', %q(Review the device's configuration and verify the use of an AAA server for Account Management. Configuration must include at least one authenticated remote AAA server and verification that authentication, authorization, and accounting are enabled. In order for AAA to execute authorizations, role-based access control (RBAC) must also be configured on the switch, as shown in the configuration example. User roles do not need to follow these exact permissions, but they must comply with organizational policies for access-control. If the AAA server is not configured to centrally manage authentication settings, this is a finding.

Using the "show running-config" command will display all configured AAA commands, which must include the following commands with the variables completed:

aaa group server [radius/tacacs] [name]
[radius/tacacs]-server host [IP Address] vrf [name] key [key]
aaa authentication login default group [group name] [radius/tacacs] [local]
aaa authentication login console [group] [group name/radius/tacacs+] [local]
aaa authentication dot1x default group [group] [radius]
aaa authentication policy on-success log
aaa authentication policy on-failure log
aaa authorization console
aaa authorization exec default [radius/tacacs] local
aaa authorization commands all default local
aaa accounting exec default start-stop logging
aaa accounting system default start-stop logging
aaa accounting commands all default start-stop logging
no aaa root

Executing the "Show aaa sessions" command will verify the operation of AAA for any connected sessions. This will include the username, role, state, authentication method, and remote host information, which must match the configured remote AAA server.

Verify Role Based Access Control is enabled by executing the "show roles" command, and review the configured roles to ensure they meet organization-defined requirements.)
  desc 'fix', 'Configure AAA services via a remote AAA server for all nonlocal accounts.

Configuration:
aaa group server [radius/tacacs] [name]
[radius/tacacs]-server host [IP Address] vrf [name] key [key]
aaa authentication login default group [group name] [radius/tacacs] [local]
aaa authentication login console [group] [group name/radius/tacacs+] [local]
aaa authentication dot1x default group [group] [radius]
aaa authentication policy on-success log
aaa authentication policy on-failure log
aaa authorization console
aaa authorization exec default [radius/tacacs] local
aaa authorization commands all default local
aaa accounting exec default start-stop logging
aaa accounting system default start-stop logging
aaa accounting commands all default start-stop logging
no aaa root

Example RBAC roles:

role administrator
 10 permit command .*

 role operator
 10 permit command show running-config [all|detail] sanitized
 20 deny command >|>>|extension|\\||session|do|delete|copy|rmdir|mkdir|python-shell|bash|platform|scp|append|redirect|tee|more|less|who|show run.*
 25 deny command bash
 30 deny mode config command (no |default ) (username|role|aaa|tcpdump|schedule|event.*)
 40 permit command .*
 30 deny mode config command (no |default ) (username|role|aaa|tcpdump|schedule|event.*)
 40 permit command .*'
  impact 0.7
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61833r2_chk'
  tag severity: 'high'
  tag gid: 'V-60885'
  tag rid: 'SV-75343r2_rule'
  tag stig_id: 'AMLS-NM-000430'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-66597r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
