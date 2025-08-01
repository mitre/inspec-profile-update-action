control 'SV-89619' do
  title 'The MQ Appliance network device must use multifactor authentication for network access to privileged accounts.'
  desc 'Multifactor authentication requires using two or more factors to achieve authenticated access to the MQ Appliance. Factors include: 

(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). 

Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. 

Verify the MQ Appliance PKI-based user authentication is configured to support multifactor authentication for network access to privileged accounts. 

Click on the Network (gear) icon. 

Under Management, click on "Web Management Service". 
Expand the settings under "Advanced". 
Click the pencil icon to the right of the custom SSL Server Profile. 

Scroll to "Validation Credentials". 
Click on the pencil icon to the right. 
For each certificate name listed, click the pencil to the right and then click "Details" to display the certificate properties. 

Verify all listed client certificates are authorized to access the MQ Appliance. 

If certificate-based multifactor authentication is not used, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. 

Configure MQ Appliance PKI-based user authentication to support multifactor authentication for network access to privileged accounts. 

Step 1: Create Crypto Certificate Object: 
- Click on the "Objects" icon. 
- Select Crypto Configuration >> Crypto Certificate >> New. 
- Provide a new crypto certificate name in the "Name" field. 
- Select "cert:///" from "File Name". 
- Click the "Upload" button. 
- Browse to the certificate file, select file, and click "Open". 
- Click "Upload". 
- Repeat process for additional certificate files as needed. 

Step 2: Create Crypto Key Object: 
- Select Crypto Configuration >> Crypto Key >> New. 
- Provide a new crypto key name in the "Name" field. 
- Select "cert:///" from "File Name". 
- Click the "Upload" button. 
- Browse to the key file, select file, and click "Open". 
- Click "Upload". 
- Repeat process for all additional certificate files previously uploaded. 

Step 3: Create Identification Credentials: 
- Select Crypto Configuration >> Crypto Identification Credentials >> New. 
- Provide a new identification credential name in the "Name" field. 
- Select a previously created crypto key object. 
- Select a previously created crypto certificate object. 
- Click on "Apply". 

Step 4: Create Crypto Validation Credentials: 
- Select Crypto Configuration >> Crypto Validation Credentials >> New. 
- Provide a new validation credential name in the "Name" field. 
- Click the "Add" button. 
- Select a crypto certificate object from the drop-down menu. 
- Repeat the Add function as needed. 
- Select Certificate Validation Mode >> Full Certificate Chain Checking. 
- Click on "Apply". 

Step 5: Create SSL Server Profile: 
- Select Crypto Configuration >> SSL Server Profile >> New. 
- Provide a new SSL Server Profile name in the "Name" field. 
- Scroll down to "Identification Credentials" and select the identification credential object. 
- Under "Client Authentication", check the following check boxes: 
--Request Client Authentication check box 
--Require Client Authentication check box 
--Validate Client Certificate check box 
- Select "Validation Credentials". 
- Select the validation credential object. 
- Click "Apply". 

Step 6: Associate SSL Server Profile with Web Management Interface: 
- Click on the Network icon. 
- Select Management >> Web Management Service. 
- Specify the unique IP address for the web management interface. 
- Expand "Advanced". 
- From the "Custom SSL Server Type" drop-down menu, select "Server Profile". 
- From the "Custom SSL Server Profile" drop-down menu, select the SSL Server profile previously created. 
- Click "Apply". 
- At the top of the page click "Save Changes".'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74945'
  tag rid: 'SV-89619r1_rule'
  tag stig_id: 'MQMH-ND-000500'
  tag gtitle: 'SRG-APP-000149-NDM-000247'
  tag fix_id: 'F-81561r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
