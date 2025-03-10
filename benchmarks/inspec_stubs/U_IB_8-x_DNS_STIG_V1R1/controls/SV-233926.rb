control 'SV-233926' do
  title 'The Infoblox DNS server implementation must maintain the integrity of information during reception.'
  desc 'Information can be unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Confidentiality is not an objective of DNS, but integrity is. DNS is responsible for maintaining the integrity of DNS information while it is being received.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable. 

1. Navigate to Data Management >> DNS >> Zones.  
2. For all external-facing authoritative zones and review all external authoritative zones. 
Note: To add "Signed" column, select an existing column >> down arrow >> Columns >> Edit Columns. Set the "Signed" check box to "Visible" and select "Apply". DNSSEC signing status will be displayed in the Zones tab. Verify that external authoritative zones are DNSSEC signed.

If DNSSEC is not used for authoritative DNS this is a finding.'
  desc 'fix', 'Note: Ensure DNSSEC is configured to meet all other STIG requirements prior to signing a zone to avoid signing with an unapproved configuration.  

1. Navigate to Data Management >> DNS >> Zones.  
2. Select the appropriate zone using the check box. Using the "DNSSEC" drop-down menu, select "Sign Zones".
3. Follow prompts to acknowledge zone signing. 
4. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37111r611298_chk'
  tag severity: 'medium'
  tag gid: 'V-233926'
  tag rid: 'SV-233926r621666_rule'
  tag stig_id: 'IDNS-8X-700021'
  tag gtitle: 'SRG-APP-000442-DNS-000067'
  tag fix_id: 'F-37076r611299_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
