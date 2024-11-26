control 'SRG-OS-000480-CLD-000090_rule' do
  title 'The Mission Owner must select and configure an Impact Level 2 FedRAMP authorized CSO when hosting Unclassified, public-releasable, DOD information.'
  desc 'FedRAMP Moderate is the minimum security baseline for all DOD cloud services. Components and Mission Owners may host Unclassified, publicly releasable DOD information on FedRAMP Moderate approved cloud services. This type of CSO is known as Impact Level 2. They may also configure an offering from the DISA PA DOD Cloud Catalog at any impact level for use.

Low Confidentiality Impact: Mission Owners will only publish, collect, store, process low confidentiality impact (sensitivity) PII in a CSO minimally possessing a FedRAMP Moderate P-ATO listed on the FedRAMP Marketplace and a DOD Level 2 PA, with Privacy Officer approval.'
  desc 'check', 'If the Cloud Service implementation is categorized as Impact Level 4/5/6, this is not applicable.

Review the approval documentation. Verify that the cloud service offering is listed in either the FedRAMP or DISA PA DOD Cloud Catalog when hosting Unclassified, public-releasable, DOD information.

If Unclassified, publicly-releasable DOD information is being hosted in the IaaS/PaaS and the cloud service offering is not listed in the FedRAMP Marketplace as FedRAMP moderate (at a minimum), or the DISA PA DOD Cloud Catalog, this is a finding.'
  desc 'fix', 'This requirement applies to Impact Level 2.
FedRAMP Moderate, High.

Select and configure an Impact Level 2 cloud service offering listed in the FedRAMP Marketplace, as FedRAMP moderate, or DISA PA DOD Cloud Catalog when hosting Unclassified, public-releasable, DOD information.'
  impact 0.5
  tag check_id: 'C-SRG-OS-000480-CLD-000090_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000480-CLD-000090'
  tag rid: 'SRG-OS-000480-CLD-000090_rule'
  tag stig_id: 'SRG-OS-000480-CLD-000090'
  tag gtitle: 'SRG-OS-000480-CLD-000090'
  tag fix_id: 'F-SRG-OS-000480-CLD-000090_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
