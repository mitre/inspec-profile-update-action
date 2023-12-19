control 'SV-79691' do
  title 'The DataPower Gateway providing intermediary services for remote access communications traffic must use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'For FIPS 140-2 Level 1 Mode: Privileged account user log on to default domain via the WebGUI >> In the search field type "crypto" >> Press "enter".

From the search results, click "Cryptographic Mode Status"; the "Cryptographic Mode Status" table is displayed.

If the "Target" is not "FIPS 140-2 Level 1", this is a finding.

For FIPS 140-2 Level 1 Mode: Privileged account user log on to default domain via the CLI >> Enter "show crypto-engine" >> Confirm "Crypto Accelerator Type" is "hsm2" >> Confirm "Crypto Accelerator Status" is "fully operational" >> Confirm "Crypto Accelerator FIPS 140-2 Level" is "3". 

If these three settings cannot be confirmed, this is a finding.'
  desc 'fix', %q(Configure FIPS 140-2 Level 1 in Firmware only.

Privileged account user log on to default domain >> In the search field type "crypto" >> Press "enter".

From the search results, click "Crypto Tools" >> Click the "Set Cryptographic Mode" tab >> From the "Cryptographic Mode" list, select "FIPS 140-2 Level 1" >> Click the "Set Cryptographic Mode" button >> When prompted to confirm cryptographic mode change, click "confirm" >> When notified that the action completed successfully, click "Close" >> click "Save Configuration". 

Restart the appliance >> Control Panel >> System Control >> Shutdown >> Select "Mode" from dropdown list: "Reboot System" >> Click "Shutdown" button >> Click "Confirm" >> Click "Close".

Configure FIPS 140-2 Level 3 Hardware Security module as follows:

Log on to the command line of the appliance.

Command Prompt >> "configure terminal"

Command Prompt >> "crypto"

Command Prompt >> "hsm-reinit hsm-domain datapower3" (see online documentation; "datapower3" refers to the name of the configured key-sharing domain)

Command Prompt >> Prompt: "Do you want to continue ('yes' or 'no')"; enter "yes"

Command Prompt >> "shutdown reboot")
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65829r4_chk'
  tag severity: 'medium'
  tag gid: 'V-65201'
  tag rid: 'SV-79691r1_rule'
  tag stig_id: 'WSDP-AG-000016'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-71141r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
