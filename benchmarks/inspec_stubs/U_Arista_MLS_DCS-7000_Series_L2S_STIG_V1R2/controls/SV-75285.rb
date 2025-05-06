control 'SV-75285' do
  title 'The Arista Multilayer Switch must re-authenticate 802.1X connected devices every hour.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes. 

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'This requirement only applies to devices required to employ 802.1X.

Verify the Arista Multilayer Switch re-authenticates 802.1X connected devices every hour. If the Arista Multilayer Switch does not re-authenticate 802.1X connected devices, this is a finding.

 This can be viewed via the "show dot1x all" command. Under the interface configuration for the .1X connected port, the following statements must be present:

ReauthPeriod : 3600 seconds

If the device does not require re-authentication, or if the re-authentication period is longer than 60 minutes, this is a finding.'
  desc 'fix', 'Configure 802.1X on the switch, using the following mandatory parameters for all applicable interfaces. Replace the bracketed variable with the applicable value.

config
interface Ethernet[X]
 switchport access vlan [Y]
 dot1x pae authenticator
 dot1x reauthentication
 dot1x port-control auto
 dot1x host-mode single-host
 dot1x timeout quiet-period [value]
 dot1x timeout reauth-period 3600
 dot1x max-reauth-req [value]

For the global configuration, include the following command statements from the global configuration mode interface:

logging level DOT1X informational
aaa authentication dot1x default group radius
dot1x system-auth-control'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series L2S'
  tag check_id: 'C-61775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60829'
  tag rid: 'SV-75285r1_rule'
  tag stig_id: 'AMLS-L2-000150'
  tag gtitle: 'SRG-NET-000338'
  tag fix_id: 'F-66539r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
