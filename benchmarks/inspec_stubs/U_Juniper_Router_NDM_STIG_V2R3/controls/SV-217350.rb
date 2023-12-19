control 'SV-217350' do
  title 'The Juniper router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of user accounts and authentication increases the administrative access to the router. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the router configuration to verify that the device is configured to use at least two authentication servers as primary source for authentication as shown in the following example:

system {
    authentication-order radius;
    }
    radius-server {
        x.x.x.x secret "$8$xYW-dsq.5zF/wYnC"; ## SECRET-DATA
    }
    radius-server {
        x.x.x.x secret "$8$xYW-dsq.5zF/wYnC"; ## SECRET-DATA
    }

If the router is not configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Step 1: Configure the authentication servers as shown in the following example:

[edit system]
set radius-server x.x.x.x secret xxxxxxxxx
set radius-server x.x.x.x secret xxxxxxxxx

Step 2: Configure the authentication order to use the authentication servers as primary source for authentication as shown in the following example:

set authentication-order radius

Note: If there is no response from the authentication server, JUNOS will authenticate using a local account as last resort. It is recommended to not configure the password at the end of the authentication order, as JUNOS will attempt to authenticate using a local account upon a rejection from the authentication server.'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18577r916100_chk'
  tag severity: 'high'
  tag gid: 'V-217350'
  tag rid: 'SV-217350r916111_rule'
  tag stig_id: 'JUNI-ND-001360'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-18575r916101_fix'
  tag 'documentable'
  tag legacy: ['SV-101289', 'V-91189']
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
