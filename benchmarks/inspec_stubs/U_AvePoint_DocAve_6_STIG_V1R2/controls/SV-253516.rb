control 'SV-253516' do
  title 'The underlying IIS platform must be configured for Smart Card (CAC) Authorization.'
  desc "Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

Multifactor authentication decreases the attack surface by virtue of the fact that attackers must obtain two factors, a physical token or a biometric and a PIN, in order to authenticate. It is not enough to simply steal a user's password to obtain access. A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet)."
  desc 'check', 'Check the Web Server (IIS) features required for Client Certificate Authentication are installed.
- On the DocAve 6 Manager server, open Server Manager, then click add/remove roles.
- Expand Web Server (IIS) >> Web Server >> Security.
- Verify that the "Client Certificate Mapping Authentication" and "Windows Authentication" features are installed.

If the features are not installed, this is a finding.

On the DocAve Manager server, open IIS Manager.
- Expand Sites and select the site used for DocAve. The default site name is DocAve6.
- Open the SSL Settings of [DocAve6] site under IIS.
- Verify the "Require SSL" checkbox is selected.
- Verify the "Require" radio button under "Client Certificates" is selected. Return to the Site Settings Home.

If the "Require SSL" checkbox is not selected, or the "Require" radio button under "Client Certificates" is not selected, this is a finding.

- Open the Authentication Settings of [DocAve6] site under IIS.
- Verify "Windows Authentication", is set to "Enable". Return to the Site Settings Home.

If "Windows Authentication", is not set to "Enable", this is a finding.

- Expand the [DocAve6] site, select Trust.
- Open the SSL Settings under IIS. 
- Check the "Require SSL" checkbox.
- Select the "Require" radio button under "Client Certificates". Return to the Site Settings Home.

If the "Require SSL" checkbox is not selected, or the "Require" radio button under "Client Certificates" is not selected, this is a finding.'
  desc 'fix', 'Install the Web Server (IIS) features required for Client Certificate Authentication.
- On the DocAve 6 Manager server, open Server Manager, then click add/remove roles.
- Expand Web Server (IIS) >> Web Server >> Security.
- Install the "Client Certificate Mapping Authentication" and "Windows Authentication" features.

On the DocAve Manager server, open IIS Manager.
- Expand Sites and select the site used for DocAve. The default site name is DocAve6.
- Open the SSL Settings of [DocAve6] site under IIS.
- Check the "Require SSL" checkbox.
- Select the "Require" radio button under "Client Certificates". Return to the Site Settings Home.
- Open the Authentication Settings of [DocAve6] site under IIS.
- Highlight "Windows Authentication" and select "Enable". Return to the Site Settings Home.
- Expand the [DocAve6] site, select Trust.
- Open the SSL Settings under IIS. 
- Check the "Require SSL" checkbox.
- Select the "Require" radio button under "Client Certificates". Return to the Site Settings Home.
- Restart the [DocAve6] Application Pool and Web Site.'
  impact 0.7
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56968r836521_chk'
  tag severity: 'high'
  tag gid: 'V-253516'
  tag rid: 'SV-253516r836523_rule'
  tag stig_id: 'DCAV-00-000057'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-56919r836522_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
