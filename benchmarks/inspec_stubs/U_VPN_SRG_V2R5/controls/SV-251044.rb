control 'SV-251044' do
  title 'The Remote Access VPN Gateway must terminate remote access network connections after an organization-defined time period.'
  desc 'This SRG requirement is in response to the DoD OIG Audit of Maintaining Cybersecurity in the Coronavirus Disease-2019 Telework Environment.

Best practice is to terminate inactive user sessions after a period; however, when setting timeouts to any VPN connection, the organization must take into consideration the risk to the mission and the purpose of the VPN. VPN connections that provide user access to the network are the prime candidates for VPN session termination and are the primary focus of this requirement.

To determine if and when the VPN connections warrant termination, the organization must perform a risk assessment to identify the use case for the VPN and determine if periodic VPN session termination puts the mission at significant risk.

The organization must document the results and the determination of the risk assessment in the VPN section of the SSP. The organization must also configure VPN session terminations in accordance with the risk assessment.
Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. 

This requirement applies to any network element that tracks individual sessions (e.g., stateful inspection firewall, ALG, or VPN).'
  desc 'check', 'This SRG requirement is in response to the DoD OIG Audit of Maintaining Cybersecurity in the Coronavirus Disease-2019 Telework Environment. VPN connections that provide user access to the network are the prime candidates for VPN session termination and are the primary focus of this requirement.

Review the system security plan. Verify the VPN gateway session  termination is configured in accordance with the value specified in the SSP.

If a risk assessment has not been conducted and an organization-defined session termination period is not addressed/documented in the SSP, this is a finding.

If the VPN gateway is not configured to terminate all remote access network connections in accordance with the values defined in the SSP, this is a finding.'
  desc 'fix', "This SRG requirement is in response to the DoD OIG Audit of Maintaining Cybersecurity in the Coronavirus Disease-2019 Telework Environment. VPN connections that provide user access to the network are the prime candidates for VPN session termination and are the primary focus of this requirement.

Conduct a risk assessment to identify the use case for the VPN and determine if periodic VPN session termination puts the mission at risk of failure.

Identify the organizations' VPN session termination periodic value based on the risk assessment. Add the results of the risk assessment and the session termination values to the site's SSP documents.

Configure the VPN gateway to periodically terminate all remote network connections in accordance with the values defined in the SSP."
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-54479r803411_chk'
  tag severity: 'medium'
  tag gid: 'V-251044'
  tag rid: 'SV-251044r803415_rule'
  tag stig_id: 'SRG-NET-000213-VPN-000721'
  tag gtitle: 'SRG-NET-000213'
  tag fix_id: 'F-54433r803413_fix'
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-000057']
  tag nist: ['SC-10', 'AC-11 a']
end
