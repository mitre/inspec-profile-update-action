control 'SV-258591' do
  title 'The ICS must terminate remote access network connections after an organization-defined time period.'
  desc 'This SRG requirement is in response to the DoD OIG Audit of Maintaining Cybersecurity in the Coronavirus Disease-2019 Telework Environment.

Best practice is to terminate inactive user sessions after a period; however, when setting timeouts to any VPN connection, the organization must take into consideration the risk to the mission and the purpose of the VPN. VPN connections that provide user access to the network are the prime candidates for VPN session termination and are the primary focus of this requirement.

To determine if and when the VPN connections warrant termination, the organization must perform a risk assessment to identify the use case for the VPN and determine if periodic VPN session termination puts the mission at significant risk.

The organization must document the results and the determination of the risk assessment in the VPN section of the SSP. The organization must also configure VPN session terminations in accordance with the risk assessment.
This SRG requirement is in response to the DOD OIG Audit of Maintaining Cybersecurity in the Coronavirus Disease-2019 Telework Environment.

Best practice is to terminate inactive user sessions after a period; however, when setting timeouts to any VPN connection, the organization must take into consideration the risk to the mission and the purpose of the VPN. VPN connections that provide user access to the network are the prime candidates for VPN session termination and are the primary focus of this requirement.

To determine if and when the VPN connections warrant termination, the organization must perform a risk assessment to identify the use case for the VPN and determine if periodic VPN session termination puts the mission at significant risk.

The organization must document the results and the determination of the risk assessment in the VPN section of the SSP. The organization must also configure VPN session terminations in accordance with the risk assessment.

Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection.

This requirement applies to any network element that tracks individual sessions (e.g., stateful inspection firewall, ALG, or VPN).'
  desc 'check', 'Verify the user role being used for CAC/PKI token VPN client logins is configured with a session timeout.

In the ICS Web UI, navigate to Administrators >> Users Roles >> User Roles.
1. Click the configured user role being used for CAC/PKI token VPN client logins.
2. Click the "Session Options" tab.

In the "Session Lifetime" section, if Idle Timeout is not set to "10", this is a finding.'
  desc 'fix', 'Configure the user role being used for CAC/PKI token VPN client logins with a session timeout.

In the ICS Web UI, navigate to Administrators >> Users Roles >> User Roles.
1. Click the configured user role being used for CAC/PKI token VPN client logins.
2. Click the "Session Options" tab.
3. In the "Session Lifetime" section, set the Idle Timeout to "10".
4. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62331r930459_chk'
  tag severity: 'medium'
  tag gid: 'V-258591'
  tag rid: 'SV-258591r930461_rule'
  tag stig_id: 'IVCS-VN-000260'
  tag gtitle: 'SRG-NET-000213-VPN-000721'
  tag fix_id: 'F-62240r930460_fix'
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-001133']
  tag nist: ['AC-11 a', 'SC-10']
end
