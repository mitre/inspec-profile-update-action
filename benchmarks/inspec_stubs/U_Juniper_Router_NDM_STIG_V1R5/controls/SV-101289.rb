control 'SV-101289' do
  title 'The Juniper router must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of user accounts and authentication increases the administrative access to the router. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the router configuration to verify that the device is configured to use an authentication server as primary source for authentication as shown in the following example:

system {
    authentication-order radius;
    }
    radius-server {
        x.x.x.x secret "$8$xYW-dsq.5zF/wYnC"; ## SECRET-DATA
    }

If the router is not configured to use an authentication server for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Step 1: Configure the authentication server as shown in the following example:

[edit system]
set radius-server x.x.x.x secret xxxxxxxxx

Step 2: Configure the authentication order to use the authentication server as primary source for authentication as shown in the following example:

set authentication-order radius

Note: If there is no response from the authentication server, JUNOS will authenticate using a local account as last resort. It is recommended to not configure password at the end of the authentication order, as JUNOS will attempt to authenticate using a local account upon a rejection from the authentication server.'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90343r2_chk'
  tag severity: 'high'
  tag gid: 'V-91189'
  tag rid: 'SV-101289r1_rule'
  tag stig_id: 'JUNI-ND-001360'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-97387r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
