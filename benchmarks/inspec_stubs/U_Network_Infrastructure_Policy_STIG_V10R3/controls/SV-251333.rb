control 'SV-251333' do
  title 'Written mission justification approval must be obtained from the Office of the DoD CIO prior to establishing a direct connection to the Internet via commercial service provider outside DoD CIO approved Internet access points (e.g. DISA IAP, Cloud Access Point, NIPRnet Federated Gateway, DREN IAP, etc.).'
  desc 'Analysis of DoD reported incidents reveal current protective measures at the NIPRNet boundary points are insufficient. Documented ISPs and validated architectures for DMZs are necessary to protect internal network resources from cyber attacks originating from external Internet sources by protective environments.'
  desc 'check', 'Any connection to an internet service provider (ISP) must be approved by the Office of the DoD CIO before a connection is made to the ISP. Based on the use cases below, verify written approval has been obtained from the Office of the DoD CIO or verify a renewal request has been appropriately submitted. There are three basic use cases for an ISP connection.  

Use case (1): An ISP connection that originates from an approved DISN infrastructure source (includes IAP connections at the DECCs). A DoDIN Waiver is required for a CC/S/A to connect the unclassified DISN to an ISP. These connection requests must come to the Waiver Panel with a Component CIO endorsement of the requirement. These connections should not be provisioned and put into use until waived. Expired waivers pending renewal from the OSD DoDIN Waiver Panel may be downgraded to a Severity 3 category, if proof of a requested renewal can be verified. A DISN enclave that cannot prove DoDIN Waiver approval for the ISP connection is a Severity 1 category. Note: If discovered during a CCRI assessment, the review team lead will immediately report the unapproved ISP connection to the USCYBERCOM (301-688-3585) and the Connection Approval Office (301-225-2900/2901). USCYBERCOM will direct the connection be immediately disconnected. 

Use Case (2): An ISP connection to a Stand Alone Enclave (physically and logically separated from any DISN connection) requires DoDIN Waiver approval prior to connection. The Stand Alone Enclave must have an AO issued ATO and the connection must be logically and physically separated from the DISN. An unapproved ISP connection in this use case will be assigned a Severity 3 category.

Use Case (3): An ISP connection to a non-DoD network (such as a contractor-owned infrastructure) co-located on the same premises as the DoD network. The non-DoD network is physically and logically separated from any DoD IP network. Furthermore, it is not connected to any DoD IP network. The non-DoD network infrastructure is not DoD funded nor is it operated or administered by DoD military or civilian personnel. In addition, the non-DoD network with the ISP connection is not storing, processing, or transmitting any DoD data. For such a network as defined herein, a DoDIN Waiver approval is not required for deploying a connection to an ISP. However, the AO must perform and have on file a risk assessment endorsed by the facility or installation command.

If any of the above use cases that are applicable and written approval has been not been obtained from the Office of the DoD CIO or if a renewal request has not been submitted, this is a finding.'
  desc 'fix', 'Written mission justification approval must be obtained from the Office of the DoD CIO prior to establishing a direct connection to the Internet via commercial service provider outside DoD CIO approved Internet access points (e.g. DISA IAP, Cloud Access Point, NIPRnet Federated Gateway, DREN IAP, etc.).'
  impact 0.7
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54768r805952_chk'
  tag severity: 'high'
  tag gid: 'V-251333'
  tag rid: 'SV-251333r805954_rule'
  tag stig_id: 'NET0160'
  tag gtitle: 'NET0160'
  tag fix_id: 'F-54721r805953_fix'
  tag 'documentable'
  tag legacy: ['V-8051', 'SV-8537']
  tag cci: ['CCI-001101', 'CCI-001121']
  tag nist: ['SC-7 (3)', 'SC-7 (14)']
end
