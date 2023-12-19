control 'SV-79693' do
  title 'The DataPower Gateway that stores secret or private keys must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder. 

Private key data associated with software certificates, including those issued to an ALG, is required to be generated and protected in at least a FIPS 140-2 Level 1 validated cryptographic module."
  desc 'check', 'For FIPS 140-2 Level 1 Mode: Privileged account user log on to default domain via the WebGUI >> In the search field type "crypto" >> Press "enter".

From the search results, click "Cryptographic Mode Status"; the "Cryptographic Mode Status" table is displayed.

If the "Target" is not "FIPS 140-2 Level 1", this is a finding.

For FIPS 140-2 Level 1 Mode: Privileged account user log on to default domain via the CLI >> Enter "show crypto-engine" >> Confirm "Crypto Accelerator Type" is "hsm2" >> Confirm "Crypto Accelerator Status" is "fully operational" >> Confirm "Crypto Accelerator FIPS 140-2 Level" is "3". 

If these three settings cannot be confirmed, this is a finding.'
  desc 'fix', %q(Configure FIPS 140-2 Level 1 in Firmware only.

Privileged account user log on to default domain >> In the search field type "crypto" >> Press "enter" >> From the search results, click "Crypto Tools" >> Click the "Set Cryptographic Mode" tab >> From the "Cryptographic Mode" list, select "FIPS 140-2 Level 1" >> Click the "Set Cryptographic Mode" button.

When prompted to confirm cryptographic mode change, click "confirm" >> When notified that the action completed successfully, click "Close" >> click "Save Configuration".

Restart the appliance >> Control Panel >> System Control >> Shutdown >> Select "Mode" from dropdown list: "Reboot System" >> Click "Shutdown" button >> Click "Confirm" >> Click "Close".

Configure FIPS 140-2 Level 3 Hardware Security module as follows:

Log on to the command line of the appliance.

Command Prompt >> "configure terminal"

Command Prompt >> "crypto"

Command Prompt >> "hsm-reinit hsm-domain datapower3" (see online documentation; "datapower3" refers to the name of the configured key-sharing domain)

Command Prompt >> prompt: "Do you want to continue ('yes' or 'no')"; enter "yes"

Command Prompt >> "shutdown reboot")
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65203'
  tag rid: 'SV-79693r1_rule'
  tag stig_id: 'WSDP-AG-000017'
  tag gtitle: 'SRG-NET-000062-ALG-000092'
  tag fix_id: 'F-71143r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
