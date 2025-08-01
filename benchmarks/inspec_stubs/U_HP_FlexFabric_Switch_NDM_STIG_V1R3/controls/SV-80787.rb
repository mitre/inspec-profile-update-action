control 'SV-80787' do
  title 'The HP FlexFabric switch must be configured to utilize an authentication server for the purpose of authenticating privilege users, managing accounts, and to centrally verify authentication settings and Personal Identity Verification (PIV) credentials.'
  desc 'To assure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system. Protecting access authorization information ensures that authorization information cannot be altered, spoofed, or otherwise compromised during transmission.

The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if it is authenticating user logon via an authentication server. Local authentication must only be used as a last resort. Example configuration would look similar to the following:

authentication login hwtacacs-scheme <name of scheme> local
or 
 authentication login radius-scheme <name of scheme> local

If the HP FlexFabric Switch does not have an authentication server configured as the primary authentication method, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to use an authentication server:

[HP] radius scheme <name of scheme>
[HP-radius-jitc] primary authentication x.x.x.x key simple xxxxxx
[HP-radius-jitc] user-name-format without-domain

[HP] domain <domain name>
[HP-isp-jitc] authentication login radius-scheme <name of scheme> local
[HP-isp-jitc] authorization login radius-scheme <name of scheme> local
[HP-isp-jitc] accounting login radius-scheme <name of scheme>c local
[HP] domain default enable <domain name>'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66297'
  tag rid: 'SV-80787r1_rule'
  tag stig_id: 'HFFS-ND-000141'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-72373r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
