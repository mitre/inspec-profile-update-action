control 'SV-104305' do
  title 'Symantec ProxySG must enable Attack Detection.'
  desc "DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Symantec ProxySG Attack Detection prevents or limits the effects of denial of service (DoS) and distributed-DoS (DDoS) attacks by limiting the number of simultaneous TCP connections and/or excessive repeated requests from each client IP address that can be established within a specified time frame. Configure attack detection for both clients and servers or server groups. The client attack-detection configuration is used to control the behavior of attacking sources. The server attack-detection configuration is used when an administrator wants to prevent a server from becoming overloaded by limiting the number of outstanding requests that are allowed.

The default settings should work in most environments, but can be fine tuned to prevent impact on the site's traffic flow. Organizations should also take into consideration the capabilities and configuration of adjacent network devices (e.g., firewalls performing packet filtering to block DoS attacks).

The default settings should work in most environments, but can be fine-tuned to prevent impact on the site's traffic flow. Organizations should also take into consideration the capabilities and configuration of adjacent network devices (e.g., firewalls performing packet filtering to block DoS attacks).

Default settings for client DDoS settings on the ProxySG are as follows.
To view Default settings for client DDoS settings on the ProxySG, type the following command at the command line interface. ProxySG#(config attack-detection)show attack-detection client

Client limits enabled:      false
Client interval:         20 minutes
Default client limits:
  Client concurrent request limit: unlimited
  Client connection limit:     100
  Client failure limit:       50
  Client request limit:       unlimited
  Client warning limit:       10
  Blocked client action:      Drop
  Client connection unblock time:  unlimited
  Monitor only mode:        disabled"
  desc 'check', 'Verify Attack Detection is enabled.

1. SSH into the ProxySG console, type "enable".
2. Enter the correct password, type "configure terminal".
3. Press "Enter", type "show attack-detection configuration".
4. Confirm that "client limits enabled" equals "true".

If Attack Detection is not enabled, this is a finding.'
  desc 'fix', 'Enable the Attack Detection function for the default settings or fine tune needed by site environment.

1. SSH into the ProxySG console, type "enable".
2. Enter the correct password, type "configure terminal". 
3. Press "Enter", and then type "attack-detection". 
4. Type "client" and press "Enter", type "enable-limits" and press "Enter".

See "Chapter 73: Preventing Denial of Service Attacks" in the ProxySG Administration Guide to understand the functionality before proceeding. Fine tune the default client limits if there is an operational impact.'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93599r1_chk'
  tag severity: 'high'
  tag gid: 'V-94413'
  tag rid: 'SV-104305r2_rule'
  tag stig_id: 'SYMP-NM-000320'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-100529r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
