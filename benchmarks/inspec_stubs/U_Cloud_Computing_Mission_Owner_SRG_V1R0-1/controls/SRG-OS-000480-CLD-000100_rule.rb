control 'SRG-OS-000480-CLD-000100_rule' do
  title 'The Mission Owner must select and configure an Impact Level 4/5 CSO listed in the DISA PA DOD Cloud Catalog when hosting Controlled Unclassified Information (CUI).'
  desc 'Impact Level 4 accommodates CUI. CUI is unclassified information that under law or policy requires protection from unauthorized disclosure as established by Executive Order 13556 (November 2010) or other mission critical data. Designating information as CUI is the responsibility of the data owner and their organization. Determination of the appropriate impact level for a specific mission with CUI and mission data will be the responsibility of the mission AO.

Impact Level 5 accommodates CUI that requires a higher level of protection as deemed necessary by the information owner, public law, or other Government regulations. Level 5 also supports unclassified National Security Systems (NSSs) due to the inclusion of NSS-specific requirements in the FedRAMP+ controls/control enhancements (C/CEs). NSS must be implemented at Level 5.'
  desc 'check', 'If the implementation is categorized as Impact Level 2 or 6, this is not applicable.

Review the approval documentation and the DISA PA Cloud Catalog. Verify that the cloud service offering is listed in the DISA PA DOD Cloud Catalog. Verify the Cloud Catalog offering is listed as Impact Level 4/5.

If sensitive but unclassified information is being hosted in the IaaS/PaaS and the cloud service offering is not listed in the DISA PA DOD Cloud Catalog, Impact Level 4/5, this is a finding.'
  desc 'fix', 'This applies to Impact Level 4/5.
FedRAMP Moderate, High.

Select and configure a CSO listed in the DISA PA DOD Cloud Catalog for use with Impact Level 4/5 or higher. Specify in the SLA with the CSP and third-party providers compliance with applicable STIG configurations.'
  impact 0.7
  tag check_id: 'C-SRG-OS-000480-CLD-000100_chk'
  tag severity: 'high'
  tag gid: 'SRG-OS-000480-CLD-000100'
  tag rid: 'SRG-OS-000480-CLD-000100_rule'
  tag stig_id: 'SRG-OS-000480-CLD-000100'
  tag gtitle: 'SRG-OS-000480-CLD-000100'
  tag fix_id: 'F-SRG-OS-000480-CLD-000100_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
