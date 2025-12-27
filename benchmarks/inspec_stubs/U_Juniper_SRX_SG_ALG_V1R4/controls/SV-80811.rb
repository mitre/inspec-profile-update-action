control 'SV-80811' do
  title 'The Juniper SRX Services Gateway Firewall must terminate all communications sessions associated with user traffic after 15 minutes or less of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

This control does not imply that the device terminates all sessions or network access; it only ends the inactive session.

Since many of the inactivity timeouts pre-defined by Junos OS are set to 1800 seconds, an explicit custom setting of 900 must be set for each application used by the DoD implementation. Since a timeout cannot be set directly on the predefined applications, the timeout must be set on the any firewall rule that uses a pre-defined application (i.e., an application that begins with junos-), otherwise the default pre-defined timeout will be used.'
  desc 'check', 'Check both the applications and protocols to ensure session inactivity timeout for communications sessions is set to 900 seconds or less.

First get a list of security policies, then enter the show details command for each policy-name found.

[edit]
show security policies
show security policy <policy-name> details

Example:
Application: any
 IP protocol: 0, ALG: 0, Inactivity timeout: 0

Verify an activity timeout is configured for either "any" application or, at a minimum, the pre-defined applications (i.e., application names starting with junos-).

To verify locally created applications, first get a list of security policies, then enter the show details command for each policy-name found.

[edit]
Show applications 
show applications application <application-name>

If an inactivity timeout value of 900 seconds or less is not set for each locally created application and pre-defined applications, this is a finding.'
  desc 'fix', 'Add or update the session inactivity timeout for communications sessions to 900 seconds or less.

Examples: 
[edit]
set applications application <application-name> term 1 protocol udp inactivity-timeout 900
set applications application junos-http inactivity-timeout 900

Or

Create a service that matches any TCP/UDP:
[edit]
set applications application TCP-ALL source-port 1-65535 destination-port 1-65535 protocol tcp inactivity-timeout 900

Note: When pre-defined applications are used in firewall policies, the timeout value must be set in the policy stanza.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66321'
  tag rid: 'SV-80811r1_rule'
  tag stig_id: 'JUSX-AG-000105'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-72397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
