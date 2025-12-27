control 'SV-79697' do
  title 'The DataPower Gateway providing intermediary services for remote access communications traffic must use NIST FIPS-validated cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'For FIPS 140-2 Level 1 Mode: Privileged account user log on to default domain via the WebGUI >> In the search field type "crypto" >> Press "enter".

From the search results, click "Cryptographic Mode Status"; the "Cryptographic Mode Status" table is displayed.

If the "Target" is not "FIPS 140-2 Level 1", this is a finding.

For FIPS 140-2 Level 1 Mode: Privileged account user log on to default domain via the CLI >> Enter "show crypto-engine" >> Confirm "Crypto Accelerator Type" is "hsm2" >> Confirm "Crypto Accelerator Status" is "fully operational" >> Confirm "Crypto Accelerator FIPS 140-2 Level" is "3". 

If these three settings cannot be confirmed, this is a finding.'
  desc 'fix', %q(Configure FIPS 140-2 Level 1 in Firmware only.

Privileged account user log on to default domain >> In the search field type "crypto" >> Press "enter" >> From the search results, click "Crypto Tools" >> Click the "Set Cryptographic Mode" tab >> From the "Cryptographic Mode" list, select "FIPS 140-2 Level 1" >> Click the "Set Cryptographic Mode" button.

When prompted to confirm cryptographic mode change, click "confirm" >> When notified that the action completed successfully, click "Close" >> Click "Save Configuration".
 
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
  tag check_id: 'C-65835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65207'
  tag rid: 'SV-79697r1_rule'
  tag stig_id: 'WSDP-AG-000019'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-71147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
